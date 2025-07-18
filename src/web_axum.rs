use crate::auth_service::AuthService;
#[cfg(feature = "web")]
use axum::{Json, Router, extract::State, routing::post};
use serde::Deserialize;
use std::sync::Arc;

#[cfg(feature = "web")]
pub async fn start_server(auth_service: Arc<AuthService>) {
    let app = Router::new()
        .route("/signup", post(signup_handler))
        .route("/login", post(login_handler))
        .route("/health", post(health_handler))
        .with_state(auth_service);

    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Axum server running at http://{}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

#[cfg(feature = "web")]
async fn signup_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> String {
    // TODO: Parse body, call AuthService.signup, return result
    "Signup endpoint stub".to_string()
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

    // Try to parse the body as LoginRequest
    let req: Result<LoginRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(login) => {
            match _auth
                .login_with_credentials(&login.username, &login.password)
                .await
            {
                Ok(token_pair) => {
                    // Return tokens as JSON
                    serde_json::json!({
                        "access_token": token_pair.access_token,
                        "refresh_token": token_pair.refresh_token
                    })
                    .to_string()
                }
                Err(e) => {
                    // Return error as JSON
                    serde_json::json!({
                        "error": e.to_string()
                    })
                    .to_string()
                }
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
