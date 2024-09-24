use axum::{
    extract::{Query, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Extension, Json, Router,
};

use hmac::{Hmac, Mac};
use jwt::{header::{HeaderContentType, HeaderType}, AlgorithmType, JoseHeader, Token, VerifyWithKey};
use log::{error, info};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use std::{
    sync::Arc, time::{SystemTime, UNIX_EPOCH}
};

use base64::{prelude::BASE64_STANDARD, Engine};

#[derive(Serialize, Deserialize, Debug)]
struct JsonError {
    error: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonMessage {
    message: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonLog {
    time: i64,
    tag: String,
    payload: String, // base64 encoded string
}

#[derive(sqlx::FromRow)]
struct SqlLog {
    time: i64,
    tag: String,
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
        .route("/", get(|| async { Json(JsonMessage { message: "healthy".to_string() }) }))
        .route("/health", get(|| async { Json(JsonMessage { message: "healthy".to_string() }) }))
        .nest("/api/v1", apiv1_routes);

    info!("server listening on 0.0.0.0:8000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone)]
struct User {
    id: String,
}

#[derive(Default, Debug, PartialEq, Serialize, Deserialize)]
struct JwtExpirationHeader {
    #[serde(rename = "alg")]
    algorithm: AlgorithmType,

    #[serde(rename = "kid", skip_serializing_if = "Option::is_none")]
    key_id: Option<String>,

    #[serde(rename = "typ", skip_serializing_if = "Option::is_none")]
    type_: Option<HeaderType>,

    #[serde(rename = "cty", skip_serializing_if = "Option::is_none")]
    content_type: Option<HeaderContentType>,

    #[serde(rename = "iat", skip_serializing_if = "Option::is_none")]
    issued_at: Option<u64>,

    #[serde(rename = "exp")]
    expiration: u64,
}

impl JoseHeader for JwtExpirationHeader {
    fn algorithm_type(&self) -> AlgorithmType {
        self.algorithm
    }

    fn key_id(&self) -> Option<&str> {
        self.key_id.as_deref()
    }

    fn type_(&self) -> Option<HeaderType> {
        self.type_
    }

    fn content_type(&self) -> Option<HeaderContentType> {
        self.content_type
    }}


#[derive(Deserialize, Debug)]
struct JwtClaims {
    sub: String
}

async fn auth_middleware(
    state: State<Arc<AppState>>,
    mut req: Request,
    next: Next,
) -> Result<Response, (StatusCode, Json<JsonError>)> {
    let auth_header = match req.headers().get(header::AUTHORIZATION) {
        Some(header) => header,
        None => {
            return Err((
                StatusCode::UNAUTHORIZED, 
                Json(JsonError { error: "no auth header given".to_string() })
            ));
        }
    };

    let Ok(header_string) = auth_header.to_str() else {
        let error_string = format!("unable to convert auth header to string: {:?}", auth_header);
        error!("{error_string}");
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR, 
            Json(JsonError { error: error_string })
        ));
    };

    if &header_string[0..7].to_lowercase() != "bearer " {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(JsonError { error: "invalid auth type, must be bearer".to_string() })
        ));
    }

    let jwt_string = &header_string[7..];

    // auth user
    let token: Token<JwtExpirationHeader, JwtClaims, _> = match jwt_string.verify_with_key(&state.auth_secret_key) {
        Ok(token) => token,
        Err(e) => return Err((
            StatusCode::UNAUTHORIZED,
            Json(JsonError { error: format!("unable to verify auth token {}: {:?}", jwt_string, e) })
        ))
    };

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(e) => {
            let error_string = format!("unable to get system time since unix epoch {:?}", e);
            error!("{error_string}");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR, 
                Json(JsonError { error: error_string }) 
            ))
        }
    };

    let headers = token.header();

    if headers.expiration <= now {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(JsonError { error: "auth token is expired".to_string() })
        ));
    }

    let claims = token.claims();

    let user = User { id: claims.sub.clone() };

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}

#[derive(Deserialize, Debug)]
struct GetLogsParams {
    limit: Option<u64>,
    offset: Option<u64>,
    start_time: Option<i64>,
    end_time: Option<i64>,
}

//const DAY_IN_NANO_SECONDS: i64 = 1000 * 1000 * 60 * 60 * 24;

async fn get_logs_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<GetLogsParams>,
    Extension(user): Extension<User>,
) -> Result<Json<Vec<JsonLog>>, (StatusCode, Json<JsonError>)> {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n,
        Err(e) => {
            let msg = format!("error getting system time: {:?}", e);
            error!("{e}");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(JsonError { error: msg })));
        }
    };

    let limit = params.limit.unwrap_or(256);
    let offset = params.offset.unwrap_or(0);
    let start_time = params.start_time.unwrap_or(0);
    let end_time = params.end_time.unwrap_or(now.as_nanos() as i64);

    match sqlx::query_as::<_, SqlLog>(
        "SELECT time, tag, payload FROM logs WHERE owner_id = $1 AND time >= $4 AND time <= $5 ORDER BY time DESC LIMIT $2 OFFSET $3;",
    )
    .bind(user.id)
    .bind(limit as i64)
    .bind(offset as i64)
    .bind(start_time)
    .bind(end_time)
    .fetch_all(&state.db_pool)
    .await
    {
        Ok(rows) => {
            return Ok(Json(
                rows.iter()
                    .map(|row| JsonLog {
                        time: row.time,
                        tag: row.tag.clone(),
                        payload: BASE64_STANDARD.encode(&row.payload[..]),
                    })
                    .collect(),
            ))
        }
        Err(e) => {
            let msg = format!("error encoding to base64: {:?}", e);
            error!("{msg}");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(JsonError { error: msg })));
        }
    }
}

async fn post_logs_handler(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<User>,
    Json(logs): Json<Vec<JsonLog>>,
) -> Result<Json<JsonMessage>, (StatusCode, Json<JsonError>)> {
    let count = logs.len();
    let log_owner_ids: Vec<String> = vec![user.id; count];
    let mut logs_timestamps: Vec<i64> = Vec::with_capacity(count);
    let mut logs_payloads: Vec<Vec<u8>> = Vec::with_capacity(count);
    let mut logs_tags: Vec<String> = Vec::with_capacity(count);

    for log in logs {
        let payload = match BASE64_STANDARD.decode(log.payload) {
            Ok(payload) => payload,
            Err(e) => {
                let msg = format!("couldn't decode base64 payload: {:?}", e);
                error!("{msg}");
                return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(JsonError { error: msg })));
            }
        };

        logs_timestamps.push(log.time);
        logs_payloads.push(payload);
        logs_tags.push(log.tag)
    }

    if let Err(e) = sqlx::query(
        "INSERT INTO logs(owner_id, time, payload, tag) SELECT * FROM UNNEST($1::text[], $2::bigint[], $3::bytea[], $4::text[])",
    )
    .bind(&log_owner_ids[..])
    .bind(&logs_timestamps[..])
    .bind(&logs_payloads[..])
    .bind(&logs_tags[..])
    .execute(&state.db_pool).await {
        let msg = format!("{e}");
        error!("{msg}");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, Json(JsonError { error: msg }))); 
    };

    return Ok(Json(JsonMessage { message: "success".to_string() }));
}
