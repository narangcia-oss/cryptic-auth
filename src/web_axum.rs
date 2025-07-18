use crate::auth_service::AuthService;
#[cfg(feature = "web")]
use axum::{Json, Router, extract::State, routing::post};
use serde::Deserialize;
use std::sync::Arc;

#[cfg(feature = "web")]
pub async fn start_server(auth_service: Arc<AuthService>) {
    use axum::serve;
    use tokio::net::TcpListener;
    let app = Router::new()
        .route("/signup", post(signup_handler))
        .route("/login", post(login_handler))
        .route("/health", post(health_handler))
        .with_state(auth_service);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Axum server running at http://{}", addr);
    let listener = TcpListener::bind(addr).await.unwrap();
    serve(listener, app).await.unwrap();
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
            // Create credentials using the password manager
            let credentials_result = crate::core::credentials::Credentials::from_plain_password(
                _auth.password_manager.as_ref(),
                signup.username.clone(),
                crate::core::credentials::PlainPassword::new(signup.password.clone()),
            )
            .await;
            match credentials_result {
                Ok(credentials) => {
                    let user =
                        crate::core::user::User::new(uuid::Uuid::new_v4().to_string(), credentials);
                    match _auth.signup(user.clone()).await {
                        Ok(_) => serde_json::json!({
                            "id": user.id,
                            "identifier": user.credentials.identifier
                        })
                        .to_string(),
                        Err(e) => serde_json::json!({
                            "error": e.to_string()
                        })
                        .to_string(),
                    }
                }
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
