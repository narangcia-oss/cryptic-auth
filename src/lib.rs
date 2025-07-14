// src/lib.rs - The Main Authentication Gateway

//! A robust and secure authentication crate.
//! It provides tools for user management, password hashing,
//! session and token management, and much more.

// Make modules public so they are accessible to crate users
pub mod auth_service;
pub mod core;
pub mod error;

// Re-export key elements for easier use
pub use auth_service::Z3AuthService;
pub use error::AuthError;

// You can add other 'use' statements here as your crate grows
// For example:
// pub use user::{User, Credentials};
// pub use token::TokenPair;
