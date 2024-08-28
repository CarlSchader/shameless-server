use axum::{
    extract::State, routing::{get, post}, Router
};
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};

use std::sync::Arc;

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

async fn post_logs_handler(State(state): State<Arc<AppState>>) {
    println!("{:?}", state);
}

