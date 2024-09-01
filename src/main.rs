use axum::{
    extract::{Query, State}, routing::{get, post}, Json, Router
};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
pub struct Log {
    pub ts: i64,
    pub payload: Vec<u8>, 
}

struct UserIdQueryParams {
    user_id: String,
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
async fn get_logs_handler(State(state): State<Arc<AppState>>) {
    println!("{:?}", state);
}

async fn post_logs_handler(State(state): State<Arc<AppState>>, Query(params): Query<UserIdQueryParams>, Json(logs): Json<Vec<Log>>) {
    let count = logs.len();
    let mut log_owner_ids: Vec<String> = vec![params.user_id; count];
    let mut logs_timestamps: Vec<i64> = Vec::with_capacity(count); 
    let mut logs_payloads: Vec<Vec<u8>> = Vec::with_capacity(count); 

    for i in 0..=count {
        logs_timestamps[i] = logs[i].ts;
        logs_payloads[i] = logs[i].payload;
    }

    sqlx::query!(
        "INSERT INTO logs(owner_id, time, payload) SELECT * FROM UNNEST($1::text[], $2::bigint[], $3::bytea[])",
        &log_owner_ids[..], 
        &logs_timestamps[..], 
        &logs_payloads[..],
    )
    .execute(&state.db_pool).await.unwrap();
}

