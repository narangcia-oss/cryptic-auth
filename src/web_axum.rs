use crate::auth_service::AuthService;
#[cfg(feature = "web")]
use axum::{Json, Router, extract::State, routing::post};
use std::sync::Arc;

#[cfg(feature = "web")]
pub async fn start_server(auth_service: Arc<AuthService>) {
    let app = Router::new()
        .route("/signup", post(signup_handler))
        .route("/login", post(login_handler))
        .route("/health", post(health_handler))
        .with_state(auth_service);

    let addr = "127.0.0.1:3000".parse().unwrap();
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
    // TODO: Parse body, call AuthService.login_with_credentials, return result
    "Login endpoint stub".to_string()
}

#[cfg(feature = "web")]
async fn health_handler() -> String {
    "OK".to_string()
}
