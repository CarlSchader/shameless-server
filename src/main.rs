use axum::{
    extract::{Query, State}, http::StatusCode, routing::{get, post}, Json, Router
};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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
    db_pool: Pool<Postgres> 
}

#[tokio::main]
async fn main() {
    let database_url = std::env::var("DATABASE_URL").unwrap();

    let pool = PgPoolOptions::new()
        .max_connections(30)
        .connect(database_url.as_str()).await.unwrap();

    let shared_state = Arc::new(AppState { 
        db_pool: pool,
    });

    let app = Router::new()
        .route("/", get(|| async { "healthy" }))
        .route("/health", get(|| async { "healthy" }))
        .route("/logs", get(get_logs_handler))
        .route("/logs", post(post_logs_handler))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[derive(Deserialize, Debug)]
struct GetLogsParams {
    user_id: String,
}

async fn get_logs_handler(State(state): State<Arc<AppState>>, Query(params): Query<GetLogsParams>) -> Result<Json<Vec<JsonLog>>, String> {
    match sqlx::query_as::<_, SqlLog>("SELECT time, payload FROM logs WHERE owner_id = $1;").bind(params.user_id)
    .fetch_all(&state.db_pool).await {
        Ok(rows) => return Ok(Json(rows.iter().map(|row| JsonLog {
            time: row.time,
            payload: BASE64_STANDARD.encode(&row.payload[..]),
        }).collect())),
        Err(e) => return Err(format!("{e}")),
    }
}

#[derive(Deserialize, Debug)]
struct PostLogsParams {
    user_id: String,
}

async fn post_logs_handler(State(state): State<Arc<AppState>>, Query(params): Query<PostLogsParams >, Json(logs): Json<Vec<JsonLog>>) -> (StatusCode, String) {
    let count = logs.len();
    let log_owner_ids: Vec<String> = vec![params.user_id; count];
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
        &logs_payloads[..],
    )
    .execute(&state.db_pool).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("{e}")); 
    };

    return (StatusCode::OK, format!("success"));
}

