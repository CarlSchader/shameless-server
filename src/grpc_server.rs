use hmac::{Hmac, Mac};
use jwt::header::{HeaderContentType, HeaderType};
use jwt::{AlgorithmType, JoseHeader, Token, VerifyWithKey};
use log::error;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use shameless::shameless_service_server::{ShamelessService, ShamelessServiceServer};
use shameless::{GetLogsRequest, Logs, Void};
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

    Server::builder().add_service(svc).serve("[::1]:8000".parse().unwrap()).await?;

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


async fn validate_user<T>(
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

    req.extensions_mut().insert(user);
    Ok(next.run(req).await)
}



#[tonic::async_trait]
impl ShamelessService for ShamelessGrpcService {
    async fn get_logs(&self, _request: Request<GetLogsRequest>) -> Result<Response<Logs>, Status> {
        unimplemented!()
    } 

    async fn post_logs(&self, _request: Request<Logs>) -> Result<Response<Void>, Status> {
        unimplemented!()
    }
}


