//! This module manages secure password hashing and verification.

pub mod argon2;
pub mod manager;

pub use argon2::Argon2PasswordManager;
pub use manager::SecurePasswordManager;
