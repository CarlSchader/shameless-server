use axum::{
    extract::{Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Extension, Json, Router,
};
use hmac::{Hmac, Mac};
use jwt::{Header, Token, VerifyWithKey};
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{prelude::BASE64_STANDARD, Engine};

#[derive(Serialize, Deserialize, Debug)]
struct JsonLog {
    time: i64,
    payload: String, // base64 encoded string
}

#[derive(sqlx::FromRow)]
struct SqlLog {
    time: i64,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct AppState {
    db_pool: Pool<Postgres>,
    auth_secret_key: Hmac<Sha256>,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let database_url = std::env::var("DATABASE_URL").unwrap();

    let db_pool = PgPoolOptions::new()
        .max_connections(30)
        .connect(database_url.as_str())
        .await
        .unwrap();

    let auth_secret = std::env::var("AUTH_SECRET").unwrap();
    let auth_secret_key: Hmac<Sha256> = Hmac::new_from_slice(auth_secret.as_bytes()).unwrap();

    let shared_state = Arc::new(AppState {
        db_pool,
        auth_secret_key,
    });

    let apiv1_routes = Router::new()
        .route("/logs", get(get_logs_handler))
        .route("/logs", post(post_logs_handler))
        .route_layer(middleware::from_fn_with_state(
            shared_state.clone(),
            auth_middleware,
        ))
        .with_state(shared_state);

    let app = Router::new()
        .route("/", get(|| async { "healthy" }))
        .route("/health", get(|| async { "healthy" }))
        .nest("/api/v1", apiv1_routes);

    info!("server listening on 0.0.0.0:8000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone)]
struct User {
    id: String,
}

async fn auth_middleware(
    state: State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = match req.headers().get(header::AUTHORIZATION) {
        Some(header) => header,
        None => {
            warn!("no auth header given");
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    let Ok(header_string) = auth_header.to_str() else {
        error!("unable to convert auth header to string: {:?}", auth_header);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    if &header_string[0..7].to_lowercase() != "bearer " {
        warn!("invalid auth type, must be bearer");
        return Err(StatusCode::BAD_REQUEST);
    }

    let jwt_string = &header_string[7..];

    // auth user
    let token: Token<Header, BTreeMap<String, String>, _> =
        match jwt_string.verify_with_key(&state.auth_secret_key) {
            Ok(token) => token,
            Err(e) => {
                error!("error verifying auth token: {:?}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        };

    let _headers = token.header();
    let claims = token.claims();

    let Some(id) = claims.get("sub") else {
        error!("no sub claim");
        return Err(StatusCode::BAD_REQUEST);
    };

    let user = User { id: id.to_string() };

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}

#[derive(Deserialize, Debug)]
struct GetLogsParams {
    from: Option<i64>, // timestamp to retrieve
}

const DAY_IN_NANO_SECONDS: i64 = 1000 * 1000 * 60 * 60 * 24;

async fn get_logs_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetLogsParams>,
    Extension(user): Extension<User>,
) -> Result<Json<Vec<JsonLog>>, String> {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n,
        Err(e) => return Err(format!("{e}")),
    };

    let mut from_time: i64 = (now.as_nanos() as i64) - DAY_IN_NANO_SECONDS;
    if let Some(from) = params.from {
        from_time = from;
    }

    match sqlx::query_as::<_, SqlLog>(
        "SELECT time, payload FROM logs WHERE owner_id = $1 AND time >= $2 ORDER BY time DESC;",
    )
    .bind(user.id)
    .bind(from_time)
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(rows) => {
            return Ok(Json(
                rows.iter()
                    .map(|row| JsonLog {
                        time: row.time,
                        payload: BASE64_STANDARD.encode(&row.payload[..]),
                    })
                    .collect(),
            ))
        }
        Err(e) => return Err(format!("{e}")),
    }
}

async fn post_logs_handler(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Json(logs): Json<Vec<JsonLog>>,
) -> (StatusCode, String) {
    let count = logs.len();
    let log_owner_ids: Vec<String> = vec![user.id; count];
    let mut logs_timestamps: Vec<i64> = Vec::with_capacity(count);
    let mut logs_payloads: Vec<Vec<u8>> = Vec::with_capacity(count);

    for log in logs {
        let payload = match BASE64_STANDARD.decode(log.payload) {
            Ok(payload) => payload,
            Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")),
        };

        logs_timestamps.push(log.time);
        logs_payloads.push(payload);
    }

    if let Err(e) = sqlx::query!(
        "INSERT INTO logs(owner_id, time, payload) SELECT * FROM UNNEST($1::text[], $2::bigint[], $3::bytea[])",
        &log_owner_ids[..], 
        &logs_timestamps[..], 
        &logs_payloads[..]
    )
    .execute(&state.db_pool).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")); 
    };

    return (StatusCode::OK, format!("success"));
}
