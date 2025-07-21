//! Web server and HTTP API integration for Cryptic using Axum.
//!
//! This module provides the Axum-based web server and HTTP API endpoints for authentication,
//! user management, and token operations. It exposes routes for signup, login, health check,
//! token refresh, and token validation, and connects them to the core authentication service.
//!
//! All endpoints expect and return JSON. Error responses are also JSON-encoded.
//!
//! # Features
//! - Only compiled and available with the `web` feature enabled.
//! - Designed for use with the `AuthService` abstraction.
//!
//! # Example
//! ```no_run
//! use cryptic::auth_service::AuthService;
//! use cryptic::web_axum::start_server;
//! use std::sync::Arc;
//! # async fn run(auth_service: Arc<AuthService>) {
//!     start_server(auth_service).await;
//! # }
//! ```
use crate::auth_service::AuthService;
#[cfg(feature = "web")]
use axum::{Json, Router, extract::State};
use serde::Deserialize;
use std::sync::Arc;

#[cfg(feature = "web")]
/// Starts the Axum web server with all authentication routes.
///
/// Binds to `0.0.0.0:3000` and serves the API endpoints for signup, login, health check,
/// token refresh, and token validation. This function does not return unless the server fails.
///
/// # Arguments
/// * `auth_service` - An `Arc` to the shared `AuthService` instance used for all authentication logic.
///
/// # Panics
/// Panics if the TCP listener cannot bind or the server fails to start.
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
/// Returns an Axum `Router` with all Cryptic authentication routes registered.
///
/// This is useful for integrating Cryptic's API into an existing Axum application or for testing.
///
/// # Arguments
/// * `auth_service` - An `Arc` to the shared `AuthService` instance.
///
/// # Returns
/// An Axum `Router` with all authentication and token endpoints.
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
/// HTTP handler for the `/signup` endpoint.
///
/// Accepts a JSON body with `username` and `password` fields, creates a new user,
/// and returns the user ID and identifier on success. On error, returns a JSON error message.
///
/// # Request JSON
/// ```json
/// { "username": "string", "password": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "id": "...", "identifier": "..." }`
/// - Error: `{ "error": "..." }`
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
            // Use the new unified signup method with credentials
            match _auth
                .signup(crate::auth_service::SignupMethod::Credentials {
                    identifier: signup.username,
                    password: signup.password,
                })
                .await
            {
                Ok((user, _tokens)) => serde_json::json!({
                    "id": user.id,
                    "identifier": user.credentials.as_ref().map(|c| &c.identifier).unwrap_or(&"".to_string())
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
/// HTTP handler for the `/login` endpoint.
///
/// Accepts a JSON body with `username` and `password` fields, authenticates the user,
/// and returns user info and tokens on success. On error, returns a JSON error message.
///
/// # Request JSON
/// ```json
/// { "username": "string", "password": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "id": "...", "identifier": "...", "access_token": "...", "refresh_token": "..." }`
/// - Error: `{ "error": "..." }`
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
                .login(crate::auth_service::LoginMethod::Credentials {
                    identifier: login.username,
                    password: login.password,
                })
                .await
            {
                Ok((user, tokens)) => serde_json::json!({
                    "id": user.id,
                    "identifier": user.credentials.as_ref().map(|c| &c.identifier).unwrap_or(&"".to_string()),
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
/// HTTP handler for the `/health` endpoint.
///
/// Returns a simple "OK" string for health checks.
async fn health_handler() -> String {
    "OK".to_string()
}

#[cfg(feature = "web")]
/// HTTP handler for the `/token/refresh` endpoint.
///
/// Accepts a JSON body with a `refresh_token` field, and returns new access and refresh tokens
/// if the refresh token is valid. On error, returns a JSON error message.
///
/// # Request JSON
/// ```json
/// { "refresh_token": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "access_token": "...", "refresh_token": "..." }`
/// - Error: `{ "error": "..." }`
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
/// HTTP handler for the `/token/validate` endpoint.
///
/// Accepts a JSON body with a `token` field, validates the access token, and returns
/// claims information if valid. On error, returns a JSON error message.
///
/// # Request JSON
/// ```json
/// { "token": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "valid": true, "subject": "...", "expiration": ... }`
/// - Error: `{ "valid": false, "error": "..." }`
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
