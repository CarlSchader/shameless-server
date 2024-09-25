use hmac::{Hmac, Mac};
use jwt::header::{HeaderContentType, HeaderType};
use jwt::{AlgorithmType, JoseHeader, Token, VerifyWithKey};
use log::error;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use shameless::shameless_service_server::{ShamelessService, ShamelessServiceServer};
use shameless::{GetLogsRequest, Log, Logs, Void};
use sqlx::postgres::PgPoolOptions;
use sqlx::{Pool, Postgres};
use tonic::transport::Server;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};


pub mod shameless {
    tonic::include_proto!("shameless");
}


#[derive(Debug)]
struct AppState {
    db_pool: Pool<Postgres>,
    auth_secret_key: Hmac<Sha256>,
}


#[derive(Debug)]
struct ShamelessGrpcService {
    state: Arc<AppState>,
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let database_url = std::env::var("DATABASE_URL").unwrap();

    let db_pool = PgPoolOptions::new()
        .max_connections(30)
        .connect(database_url.as_str())
        .await
        .unwrap();

    let auth_secret = std::env::var("AUTH_SECRET").unwrap();
    let auth_secret_key: Hmac<Sha256> = Hmac::new_from_slice(auth_secret.as_bytes()).unwrap();

    let state = Arc::new(AppState {
        db_pool,
        auth_secret_key,
    });

    let shameless_grpc_service = ShamelessGrpcService { state };

    let svc = ShamelessServiceServer::new(shameless_grpc_service);

    Server::builder()
        .add_service(svc).serve("0.0.0.0:8000".parse().unwrap()).await?;

    Ok(())
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


#[derive(Clone)]
struct User {
    id: String,
}


fn validate_user<T>(
    req: &Request<T>,
    auth_secret_key: &Hmac<Sha256>,
) -> Result<User, Status> {
    let header_string = match req.metadata().get("Authorization") {
        Some(header_metadata) => match header_metadata.to_str() {
            Ok(header) => header,
            Err(e) => {
                let message = format!("unable to convert auth header to string: {e}");
                error!("{message}");
                return Err(Status::internal(message));
            }
        },
        None => {
            return Err(Status::unauthenticated("no auth header given"));
        }
    };

    if &header_string[0..7].to_lowercase() != "bearer " {
        return Err(Status::invalid_argument("invalid auth type, must be bearer"));
    }


    let jwt_string = &header_string[7..];

    // auth user
    let token: Token<JwtExpirationHeader, JwtClaims, _> = match jwt_string.verify_with_key(auth_secret_key) {
        Ok(token) => token,
        Err(e) => return Err(Status::unauthenticated(format!("unable to verify auth token {}: {:?}", jwt_string, e))),
    };

    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(n) => n.as_secs(),
        Err(e) => {
            let error_string = format!("unable to get system time since unix epoch {:?}", e);
            error!("{error_string}");
            return Err(Status::internal(error_string))
        }
    };

    let headers = token.header();

    if headers.expiration <= now {
        return Err(Status::unauthenticated("auth token is expired"));
    }

    let claims = token.claims();

    let user = User { id: claims.sub.clone() };
    
    Ok(user)
}


#[derive(sqlx::FromRow)]
struct SqlLog {
    time: i64,
    tag: String,
    payload: Vec<u8>,
}


#[tonic::async_trait]
impl ShamelessService for ShamelessGrpcService {
    async fn get_logs(&self, req: Request<GetLogsRequest>) -> Result<Response<Logs>, Status> {
        let user = match validate_user(&req, &self.state.auth_secret_key) {
            Ok(u) => u,
            Err(e) => return Err(e),
        };

        let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(n) => n,
            Err(e) => {
                let msg = format!("error getting system time: {:?}", e);
                error!("{e}");
                return Err(Status::invalid_argument(msg));
            }
        };

        let get_logs_req = req.get_ref();

        let limit = get_logs_req .limit.unwrap_or(256);
        let offset = get_logs_req.offset.unwrap_or(0);
        let start_time = get_logs_req.start_time.unwrap_or(0);
        let end_time = get_logs_req.end_time.unwrap_or(now.as_nanos() as i64);

        let logs_vec: Vec<Log> = match sqlx::query_as::<_, SqlLog>(
            "SELECT time, tag, payload FROM logs WHERE owner_id = $1 AND time >= $4 AND time <= $5 ORDER BY time DESC LIMIT $2 OFFSET $3;",
        )
        .bind(user.id)
        .bind(limit as i64)
        .bind(offset as i64)
        .bind(start_time)
        .bind(end_time)
        .fetch_all(&self.state.db_pool)
        .await
        {
            Ok(rows) => rows.iter()
                .map(|row| Log {
                    time: row.time,
                    tag: row.tag.clone(),
                    payload: row.payload.clone(),
                })
                .collect(),
            Err(e) => {
                let msg = format!("error deserializing logs from sql: {:?}", e);
                error!("{msg}");
                return Err(Status::invalid_argument(msg));
            }
        };
       
        Ok(Response::new(Logs { logs: logs_vec }))
    } 

    async fn post_logs(&self, req: Request<Logs>) -> Result<Response<Void>, Status> {
        let user = match validate_user(&req, &self.state.auth_secret_key) {
            Ok(u) => u,
            Err(e) => return Err(e),
        };

        let logs_ref = req.get_ref();
        let count = logs_ref.logs.len();
        let log_owner_ids: Vec<String> = vec![user.id; count];
        let mut logs_timestamps: Vec<i64> = Vec::with_capacity(count);
        let mut logs_payloads: Vec<Vec<u8>> = Vec::with_capacity(count);
        let mut logs_tags: Vec<String> = Vec::with_capacity(count);

        for log in &logs_ref.logs[..] {
            logs_timestamps.push(log.time);
            logs_payloads.push(log.payload.clone());
            logs_tags.push(log.tag.clone())
        }

        if let Err(e) = sqlx::query(
            "INSERT INTO logs(owner_id, time, payload, tag) SELECT * FROM UNNEST($1::text[], $2::bigint[], $3::bytea[], $4::text[])",
        )
        .bind(&log_owner_ids[..])
        .bind(&logs_timestamps[..])
        .bind(&logs_payloads[..])
        .bind(&logs_tags[..])
        .execute(&self.state.db_pool).await {
            let msg = format!("{e}");
            error!("{msg}");
            return Err(Status::internal(msg)); 
        };

        Ok(Response::new(Void {}))
    }
}


