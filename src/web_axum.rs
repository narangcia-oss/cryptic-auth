use crate::auth_service::AuthService;
#[cfg(feature = "web")]
use axum::{Json, Router, extract::State};
use serde::Deserialize;
use std::sync::Arc;

#[cfg(feature = "web")]
pub async fn start_server(auth_service: Arc<AuthService>) {
    use axum::routing::{get, post};
    use axum::serve;
    use tokio::net::TcpListener;
    let app = Router::new()
        .route("/signup", post(signup_handler))
        .route("/login", post(login_handler))
        .route("/health", get(health_handler).post(health_handler))
        .route("/token/refresh", post(refresh_token_handler))
        .route("/token/validate", post(validate_token_handler))
        .with_state(auth_service);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Axum server running at http://{addr}");
    let listener = TcpListener::bind(addr).await.unwrap();
    serve(listener, app).await.unwrap();
}

#[cfg(feature = "web")]
pub fn get_cryptic_axum_router(auth_service: Arc<AuthService>) -> Router {
    use axum::routing::{get, post};
    Router::new()
        .route("/signup", post(signup_handler))
        .route("/login", post(login_handler))
        .route("/health", get(health_handler).post(health_handler))
        .route("/token/refresh", post(refresh_token_handler))
        .route("/token/validate", post(validate_token_handler))
        .with_state(auth_service)
}

#[cfg(feature = "web")]
async fn signup_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> String {
    #[derive(Deserialize)]
    struct SignupRequest {
        username: String,
        password: String,
    }

    let req: Result<SignupRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(signup) => {
            // Create user using the password manager and plain password
            let user_result = crate::core::user::User::with_plain_password(
                _auth.password_manager.as_ref(),
                uuid::Uuid::new_v4().to_string(),
                signup.username.clone(),
                crate::core::credentials::PlainPassword::new(signup.password.clone()),
            )
            .await;
            match user_result {
                Ok(user) => match _auth.signup(user.clone()).await {
                    Ok(_) => serde_json::json!({
                        "id": user.id,
                        "identifier": user.credentials.identifier
                    })
                    .to_string(),
                    Err(e) => serde_json::json!({
                        "error": e.to_string()
                    })
                    .to_string(),
                },
                Err(e) => serde_json::json!({
                    "error": e.to_string()
                })
                .to_string(),
            }
        }
        Err(e) => serde_json::json!({
            "error": format!("Invalid request body: {}", e)
        })
        .to_string(),
    }
}

#[cfg(feature = "web")]
async fn login_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> String {
    #[derive(Deserialize)]
    struct LoginRequest {
        username: String,
        password: String,
    }

    let req: Result<LoginRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(login) => {
            match _auth
                .login_with_credentials_and_tokens(&login.username, &login.password)
                .await
            {
                Ok((user, tokens)) => serde_json::json!({
                    "id": user.id,
                    "identifier": user.credentials.identifier,
                    "access_token": tokens.access_token,
                    "refresh_token": tokens.refresh_token
                })
                .to_string(),
                Err(e) => serde_json::json!({
                    "error": e.to_string()
                })
                .to_string(),
            }
        }
        Err(e) => serde_json::json!({
            "error": format!("Invalid request body: {}", e)
        })
        .to_string(),
    }
}

#[cfg(feature = "web")]
async fn health_handler() -> String {
    "OK".to_string()
}

#[cfg(feature = "web")]
async fn refresh_token_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> String {
    #[derive(Deserialize)]
    struct RefreshRequest {
        refresh_token: String,
    }

    let req: Result<RefreshRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(refresh) => match _auth.refresh_access_token(&refresh.refresh_token).await {
            Ok(tokens) => serde_json::json!({
                "access_token": tokens.access_token,
                "refresh_token": tokens.refresh_token
            })
            .to_string(),
            Err(e) => serde_json::json!({
                "error": e.to_string()
            })
            .to_string(),
        },
        Err(e) => serde_json::json!({
            "error": format!("Invalid request body: {}", e)
        })
        .to_string(),
    }
}

#[cfg(feature = "web")]
async fn validate_token_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> String {
    #[derive(Deserialize)]
    struct ValidateRequest {
        token: String,
    }

    let req: Result<ValidateRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(validate) => match _auth.validate_access_token(&validate.token).await {
            Ok(claims) => serde_json::json!({
                "valid": true,
                "subject": claims.get_subject(),
                "expiration": claims.get_expiration()
            })
            .to_string(),
            Err(e) => serde_json::json!({
                "valid": false,
                "error": e.to_string()
            })
            .to_string(),
        },
        Err(e) => serde_json::json!({
            "error": format!("Invalid request body: {}", e)
        })
        .to_string(),
    }
}
