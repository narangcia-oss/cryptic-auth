// src/lib.rs - The Main Authentication Gateway

//! A robust and secure authentication crate.
//! It provides tools for user management, password hashing,
//! session and token management, and much more.

// Make modules public so they are accessible to crate users
pub mod auth_service;
pub mod core;
pub mod error;
#[cfg(feature = "postgres")]
pub mod postgres;
#[cfg(feature = "web")]
pub mod web_axum;

// Re-export key elements for easier use
pub use auth_service::AuthService;
pub use error::AuthError;
#[cfg(feature = "web")]
pub use web_axum::get_cryptic_axum_router;
#[cfg(feature = "web")]
pub use web_axum::start_server;
