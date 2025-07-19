//! # Axum Web Server Example for Narangcia Cryptic
//!
//! This example demonstrates how to run the authentication service as a web server using Axum.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example web_server --features web
//! ```
//!
//! The server will start on http://0.0.0.0:3000
//!
//! ### Endpoints
//!
//! - POST /signup {"username": "alice", "password": "secret123"}
//!
//! curl -X POST http://localhost:3000/signup \
//!  -H "Content-Type: application/json" \
//!  -d '{"username": "alice", "password": "secret123"}'
//!
//! - POST /login {"username": "alice", "password": "secret123"}
//!
//! curl -X POST http://localhost:3000/login \
//!  -H "Content-Type: application/json" \
//!  -d '{"username": "alice", "password": "secret123"}'
//!
//! - POST /health
//!
//! curl -X POST http://localhost:3000/health
//! 
//! ## Notes
//!
//! - Requires the `web` feature flag.
//! - Uses in-memory storage (no persistence).

use narangcia_cryptic::{AuthService, web_axum::start_server};
use std::sync::Arc;

#[tokio::main]
async fn main() {
    // Initialize logging
    env_logger::init();

    let auth_service = Arc::new(AuthService::default());
    #[cfg(feature = "web")]
    start_server(auth_service).await;
    #[cfg(not(feature = "web"))]
    println!("Please enable the 'web' feature to run the web server example.");
}
