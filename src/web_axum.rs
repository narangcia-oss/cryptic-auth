//! Web server and HTTP API integration for Cryptic using Axum.
//!
//! This module provides the Axum-based web server and HTTP API endpoints for authentication,
//! user management, token operations, and OAuth2 integration. It exposes routes for signup,
//! login, health check, token refresh, token validation, OAuth2 authorization, and OAuth2
//! callbacks, connecting them to the core authentication service.
//!
//! All endpoints expect and return JSON. Error responses are also JSON-encoded.
//!
//! # Features
//! - Only compiled and available with the `web` feature enabled.
//! - Designed for use with the `AuthService` abstraction.
//! - Full OAuth2 support for Google, GitHub, Discord, and Microsoft.
//!
//! # Credentials-based Flow
//! 1. POST `/login` - Authenticate user and return access token
//! Body: `{ "username": "string", "password": "string" }`
//! 2. POST `/token/refresh` - Refresh access token using refresh token
//! Body: `{ "refresh_token": "string" }`
//! 3. POST `/token/validate` - Validate access token and return claims
//! Body: `{ "token": "string" }`
//! 4. GET `/health` - Simple health check endpoint
//! 5. POST `/signup` - Create new user and return access token
//! Body: `{ "username": "string", "password": "string" }`
//!
//! # OAuth2 Flow
//! 1. GET `/oauth/{provider}/auth?state=...&scopes=...` - Generate authorization URL
//! 2. User is redirected to provider for authorization
//! 3. Provider redirects back to GET `/oauth/{provider}/callback?code=...&state=...`
//! 4. Or use POST `/oauth/login` or `/oauth/signup` with code and state
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
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;

#[cfg(feature = "web")]
/// Starts the Axum web server with all authentication routes.
///
/// Binds to `0.0.0.0:3000` and serves the API endpoints for signup, login, health check,
/// token refresh, token validation, and OAuth2 integration (authorization URLs, callbacks,
/// OAuth login/signup). This function does not return unless the server fails.
///
/// # Arguments
/// * `auth_service` - An `Arc` to the shared `AuthService` instance used for all authentication logic.
///
/// # Panics
/// Panics if the TCP listener cannot bind or the server fails to start.
pub async fn start_server(
    auth_service: Arc<AuthService>,
    address: impl Into<Option<std::net::SocketAddr>>,
) {
    use axum::serve;
    use tokio::net::TcpListener;
    let app = get_cryptic_axum_router(auth_service.clone());

    let addr = address
        .into()
        .unwrap_or_else(|| std::net::SocketAddr::from(([0, 0, 0, 0], 3000)));
    log::info!("Axum server running at http://{addr}");
    let listener = TcpListener::bind(addr).await.unwrap();
    serve(listener, app).await.unwrap();
}

#[cfg(feature = "web")]
/// Returns an Axum `Router` with all Cryptic authentication routes registered.
///
/// This is useful for integrating Cryptic's API into an existing Axum application or for testing.
/// Includes all authentication endpoints: credentials-based signup/login, token operations,
/// and OAuth2 integration with support for Google, GitHub, Discord, and Microsoft.
///
/// # Arguments
/// * `auth_service` - An `Arc` to the shared `AuthService` instance.
///
/// # Returns
/// An Axum `Router` with all authentication, token, and OAuth2 endpoints.
pub fn get_cryptic_axum_router(auth_service: Arc<AuthService>) -> Router {
    use axum::routing::{get, post};
    Router::new()
        .route("/signup", post(signup_handler))
        .route("/login", post(login_handler))
        .route("/health", get(health_handler).post(health_handler))
        .route("/token/refresh", post(refresh_token_handler))
        .route("/token/validate", post(validate_token_handler))
        .route("/oauth/{provider}/auth", get(oauth_auth_handler))
        .route("/oauth/{provider}/callback", get(oauth_callback_handler))
        .route("/oauth/signup", post(oauth_signup_handler))
        .route("/oauth/login", post(oauth_login_handler))
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
) -> Response {
    log::info!("Received /signup request: {_body}");
    #[derive(Deserialize)]
    struct SignupRequest {
        username: String,
        password: String,
    }

    let req: Result<SignupRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(signup) => {
            log::info!(
                "Attempting signup for user: {username}",
                username = signup.username
            );
            // Use the new unified signup method with credentials
            match _auth
                .signup(crate::auth_service::SignupMethod::Credentials {
                    identifier: signup.username,
                    password: signup.password,
                })
                .await
            {
                Ok((user, _tokens)) => {
                    log::info!("Signup successful for user_id: {id}", id = user.id);
                    serde_json::json!({
                        "id": user.id,
                        "identifier": user.credentials.as_ref().map(|c| &c.identifier).unwrap_or(&"".to_string())
                    })
                    .to_string().into_response()
                }
                Err(e) => {
                    log::error!("Signup failed: {e}");
                    (
                        axum::http::StatusCode::BAD_REQUEST,
                        serde_json::json!({
                            "error": e.to_string()
                        })
                        .to_string(),
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            log::error!("Invalid signup request body: {e}");
            (
                axum::http::StatusCode::BAD_REQUEST,
                serde_json::json!({
                    "error": format!("Invalid request body: {e}")
                })
                .to_string(),
            )
                .into_response()
        }
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
    log::info!("Received /login request: {_body}");
    #[derive(Deserialize)]
    struct LoginRequest {
        username: String,
        password: String,
    }

    let req: Result<LoginRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(login) => {
            log::info!(
                "Attempting login for user: {username}",
                username = login.username
            );
            match _auth
                .login(crate::auth_service::LoginMethod::Credentials {
                    identifier: login.username,
                    password: login.password,
                })
                .await
            {
                Ok((user, tokens)) => {
                    log::info!("Login successful for user_id: {id}", id = user.id);
                    serde_json::json!({
                        "id": user.id,
                        "identifier": user.credentials.as_ref().map(|c| &c.identifier).unwrap_or(&"".to_string()),
                        "access_token": tokens.access_token,
                        "refresh_token": tokens.refresh_token
                    })
                    .to_string()
                }
                Err(e) => {
                    log::info!("Login failed: {e}");
                    serde_json::json!({
                        "error": e.to_string()
                    })
                    .to_string()
                }
            }
        }
        Err(e) => {
            log::info!("Invalid login request body: {e}");
            serde_json::json!({
                "error": format!("Invalid request body: {e}")
            })
            .to_string()
        }
    }
}

#[cfg(feature = "web")]
/// HTTP handler for the `/health` endpoint.
///
/// Returns a simple "OK" string for health checks.
async fn health_handler() -> String {
    log::info!("Received /health request");
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
    log::info!("Received /token/refresh request: {_body}");
    #[derive(Deserialize)]
    struct RefreshRequest {
        refresh_token: String,
    }

    let req: Result<RefreshRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(refresh) => {
            log::info!("Attempting token refresh");
            match _auth.refresh_access_token(&refresh.refresh_token).await {
                Ok(tokens) => {
                    log::info!("Token refresh successful");
                    serde_json::json!({
                        "access_token": tokens.access_token,
                        "refresh_token": tokens.refresh_token
                    })
                    .to_string()
                }
                Err(e) => {
                    log::info!("Token refresh failed: {e}");
                    serde_json::json!({
                        "error": e.to_string()
                    })
                    .to_string()
                }
            }
        }
        Err(e) => {
            log::info!("Invalid refresh token request body: {e}");
            serde_json::json!({
                "error": format!("Invalid request body: {}", e)
            })
            .to_string()
        }
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
    log::info!("Received /token/validate request: {_body}");
    #[derive(Deserialize)]
    struct ValidateRequest {
        token: String,
    }

    let req: Result<ValidateRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(validate) => {
            log::info!("Validating access token");
            match _auth.validate_access_token(&validate.token).await {
                Ok(claims) => {
                    log::info!(
                        "Token valid for subject: {subject}",
                        subject = claims.get_subject()
                    );
                    serde_json::json!({
                        "valid": true,
                        "subject": claims.get_subject(),
                        "expiration": claims.get_expiration()
                    })
                    .to_string()
                }
                Err(e) => {
                    log::info!("Token validation failed: {e}");
                    serde_json::json!({
                        "valid": false,
                        "error": e.to_string()
                    })
                    .to_string()
                }
            }
        }
        Err(e) => {
            log::info!("Invalid validate token request body: {e}");
            serde_json::json!({
                "error": format!("Invalid request body: {}", e)
            })
            .to_string()
        }
    }
}

#[cfg(feature = "web")]
/// HTTP handler for the `/oauth/{provider}/auth` endpoint.
///
/// Generates an OAuth2 authorization URL for the specified provider.
/// Accepts query parameters for state and optional scopes.
///
/// # Query Parameters
/// - `state`: Required state parameter for CSRF protection
/// - `scopes`: Optional comma-separated list of additional scopes
///
/// # Response JSON
/// - Success: `{ "auth_url": "..." }`
/// - Error: `{ "error": "..." }`
async fn oauth_auth_handler(
    State(_auth): State<Arc<AuthService>>,
    Path(provider_str): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> String {
    log::info!("Received /oauth/{provider_str}/auth request with params: {params:?}");
    // Parse the provider from the path parameter
    let provider = match provider_str.to_lowercase().as_str() {
        "google" => crate::core::oauth::store::OAuth2Provider::Google,
        "github" => crate::core::oauth::store::OAuth2Provider::GitHub,
        "discord" => crate::core::oauth::store::OAuth2Provider::Discord,
        "microsoft" => crate::core::oauth::store::OAuth2Provider::Microsoft,
        _ => {
            return serde_json::json!({
                "error": format!("Unsupported OAuth2 provider: {}", provider_str)
            })
            .to_string();
        }
    };

    // Get the state parameter (required)
    let state = match params.get("state") {
        Some(state) => state,
        None => {
            return serde_json::json!({
                "error": "Missing required 'state' parameter"
            })
            .to_string();
        }
    };

    // Parse optional scopes parameter
    let scopes = params
        .get("scopes")
        .map(|s| s.split(',').map(|scope| scope.trim().to_string()).collect());

    // Generate the OAuth2 authorization URL
    match _auth
        .generate_oauth2_auth_url(provider, state, scopes)
        .await
    {
        Ok(auth_url) => {
            log::info!("Generated OAuth2 auth URL for provider: {provider_str}");
            serde_json::json!({
                "auth_url": auth_url
            })
            .to_string()
        }
        Err(e) => {
            log::info!("OAuth2 auth URL generation failed: {e}");
            serde_json::json!({
                "error": e.to_string()
            })
            .to_string()
        }
    }
}

#[cfg(feature = "web")]
/// HTTP handler for the `/oauth/{provider}/callback` endpoint.
///
/// Handles OAuth2 callback from providers. This endpoint would typically be called
/// by the OAuth2 provider after user authorization. Returns user info and tokens.
///
/// # Query Parameters
/// - `code`: The authorization code from the provider
/// - `state`: The state parameter for CSRF verification
///
/// # Response JSON
/// - Success: `{ "id": "...", "access_token": "...", "refresh_token": "..." }`
/// - Error: `{ "error": "..." }`
async fn oauth_callback_handler(
    State(_auth): State<Arc<AuthService>>,
    Path(provider_str): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> String {
    log::info!("Received /oauth/{provider_str}/callback request with params: {params:?}");
    // Parse the provider from the path parameter
    let provider = match provider_str.to_lowercase().as_str() {
        "google" => crate::core::oauth::store::OAuth2Provider::Google,
        "github" => crate::core::oauth::store::OAuth2Provider::GitHub,
        "discord" => crate::core::oauth::store::OAuth2Provider::Discord,
        "microsoft" => crate::core::oauth::store::OAuth2Provider::Microsoft,
        _ => {
            return serde_json::json!({
                "error": format!("Unsupported OAuth2 provider: {}", provider_str)
            })
            .to_string();
        }
    };

    // Get required parameters
    let code = match params.get("code") {
        Some(code) => code,
        None => {
            return serde_json::json!({
                "error": "Missing required 'code' parameter"
            })
            .to_string();
        }
    };

    let state = match params.get("state") {
        Some(state) => state,
        None => {
            return serde_json::json!({
                "error": "Missing required 'state' parameter"
            })
            .to_string();
        }
    };

    // Use the login method with OAuth2
    match _auth
        .login(crate::auth_service::LoginMethod::OAuth2 {
            provider,
            code: code.clone(),
            state: state.clone(),
        })
        .await
    {
        Ok((user, tokens)) => {
            log::info!(
                "OAuth2 callback login successful for user_id: {id}",
                id = user.id
            );
            serde_json::json!({
                "id": user.id,
                "access_token": tokens.access_token,
                "refresh_token": tokens.refresh_token
            })
            .to_string()
        }
        Err(e) => {
            log::info!("OAuth2 callback login failed: {e}");
            serde_json::json!({
                "error": e.to_string()
            })
            .to_string()
        }
    }
}

#[cfg(feature = "web")]
/// HTTP handler for the `/oauth/signup` endpoint.
///
/// Handles OAuth2 signup/registration using an authorization code.
/// Creates a new user account or links to existing account.
///
/// # Request JSON
/// ```json
/// { "provider": "google|github|discord|microsoft", "code": "string", "state": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "id": "...", "access_token": "...", "refresh_token": "..." }`
/// - Error: `{ "error": "..." }`
async fn oauth_signup_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> String {
    log::info!("Received /oauth/signup request: {_body}");
    #[derive(Deserialize)]
    struct OAuth2SignupRequest {
        provider: String,
        code: String,
        state: String,
    }

    let req: Result<OAuth2SignupRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(signup) => {
            log::info!(
                "Attempting OAuth2 signup for provider: {provider}",
                provider = signup.provider
            );
            // Parse the provider
            let provider = match signup.provider.to_lowercase().as_str() {
                "google" => crate::core::oauth::store::OAuth2Provider::Google,
                "github" => crate::core::oauth::store::OAuth2Provider::GitHub,
                "discord" => crate::core::oauth::store::OAuth2Provider::Discord,
                "microsoft" => crate::core::oauth::store::OAuth2Provider::Microsoft,
                _ => {
                    log::info!(
                        "Unsupported OAuth2 provider: {provider}",
                        provider = signup.provider
                    );
                    return serde_json::json!({
                        "error": format!("Unsupported OAuth2 provider: {}", signup.provider)
                    })
                    .to_string();
                }
            };

            // Use the unified signup method with OAuth2
            match _auth
                .signup(crate::auth_service::SignupMethod::OAuth2 {
                    provider,
                    code: signup.code,
                    state: signup.state,
                })
                .await
            {
                Ok((user, tokens)) => {
                    log::info!("OAuth2 signup successful for user_id: {id}", id = user.id);
                    serde_json::json!({
                        "id": user.id,
                        "access_token": tokens.access_token,
                        "refresh_token": tokens.refresh_token
                    })
                    .to_string()
                }
                Err(e) => {
                    log::info!("OAuth2 signup failed: {e}");
                    serde_json::json!({
                        "error": e.to_string()
                    })
                    .to_string()
                }
            }
        }
        Err(e) => {
            log::info!("Invalid OAuth2 signup request body: {e}");
            serde_json::json!({
                "error": format!("Invalid request body: {}", e)
            })
            .to_string()
        }
    }
}

#[cfg(feature = "web")]
/// HTTP handler for the `/oauth/login` endpoint.
///
/// Handles OAuth2 login using an authorization code.
/// Authenticates existing user or creates account if needed.
///
/// # Request JSON
/// ```json
/// { "provider": "google|github|discord|microsoft", "code": "string", "state": "string" }
/// ```
///
/// # Response JSON
/// - Success: `{ "id": "...", "access_token": "...", "refresh_token": "..." }`
/// - Error: `{ "error": "..." }`
async fn oauth_login_handler(
    State(_auth): State<Arc<AuthService>>,
    Json(_body): Json<serde_json::Value>,
) -> String {
    log::info!("Received /oauth/login request: {_body}");
    #[derive(Deserialize)]
    struct OAuth2LoginRequest {
        provider: String,
        code: String,
        state: String,
    }

    let req: Result<OAuth2LoginRequest, _> = serde_json::from_value(_body);
    match req {
        Ok(login) => {
            log::info!(
                "Attempting OAuth2 login for provider: {provider}",
                provider = login.provider
            );
            // Parse the provider
            let provider = match login.provider.to_lowercase().as_str() {
                "google" => crate::core::oauth::store::OAuth2Provider::Google,
                "github" => crate::core::oauth::store::OAuth2Provider::GitHub,
                "discord" => crate::core::oauth::store::OAuth2Provider::Discord,
                "microsoft" => crate::core::oauth::store::OAuth2Provider::Microsoft,
                _ => {
                    log::info!(
                        "Unsupported OAuth2 provider: {provider}",
                        provider = login.provider
                    );
                    return serde_json::json!({
                        "error": format!("Unsupported OAuth2 provider: {}", login.provider)
                    })
                    .to_string();
                }
            };

            // Use the unified login method with OAuth2
            match _auth
                .login(crate::auth_service::LoginMethod::OAuth2 {
                    provider,
                    code: login.code,
                    state: login.state,
                })
                .await
            {
                Ok((user, tokens)) => {
                    log::info!("OAuth2 login successful for user_id: {id}", id = user.id);
                    serde_json::json!({
                        "id": user.id,
                        "access_token": tokens.access_token,
                        "refresh_token": tokens.refresh_token
                    })
                    .to_string()
                }
                Err(e) => {
                    log::info!("OAuth2 login failed: {e}");
                    serde_json::json!({
                        "error": e.to_string()
                    })
                    .to_string()
                }
            }
        }
        Err(e) => {
            log::info!("Invalid OAuth2 login request body: {e}");
            serde_json::json!({
                "error": format!("Invalid request body: {}", e)
            })
            .to_string()
        }
    }
}
