//! This module manages secure password hashing and verification.

pub mod manager;
pub mod argon2;

pub use manager::SecurePasswordManager;
pub use argon2::Argon2PasswordManager;
