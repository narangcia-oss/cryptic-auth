//! Password management trait for secure password hashing and verification.
//!
//! This module defines the [`SecurePasswordManager`] trait, which provides an abstraction
//! for securely hashing and verifying passwords. Implementations of this trait are responsible
//! for using cryptographically secure algorithms to protect user credentials.
//!
//! # Example
//!
//! ```rust,ignore
//! use your_crate::core::password::manager::SecurePasswordManager;
//!
//! struct MyPasswordManager;
//!
//! #[async_trait::async_trait]
//! impl SecurePasswordManager for MyPasswordManager {
//!     async fn hash_password(&self, password: &str) -> Result<String, AuthError> {
//!         // Implementation here
//!         Ok("hashed".to_string())
//!     }
//!
//!     async fn verify_password(&self, password: &str, hashed_password: &str) -> Result<bool, AuthError> {
//!         // Implementation here
//!         Ok(true)
//!     }
//! }
//! ```

use crate::error::AuthError;

#[async_trait::async_trait]
/// Trait for secure password management, including hashing and verification.
///
/// Implement this trait to provide password hashing and verification using a secure algorithm
/// (e.g., Argon2, bcrypt, scrypt). The trait is asynchronous to support non-blocking operations
/// in environments where password hashing may be computationally expensive.
#[async_trait::async_trait]
pub trait SecurePasswordManager {
    /// Hashes a plaintext password using a secure algorithm.
    ///
    /// # Arguments
    ///
    /// * `password` - The plaintext password to hash.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` containing the hashed password if successful.
    /// * `Err(AuthError)` if hashing fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let hashed = manager.hash_password("my_password").await?;
    /// ```
    async fn hash_password(&self, password: &str) -> Result<String, AuthError>;

    /// Verifies a plaintext password against a hashed password.
    ///
    /// # Arguments
    ///
    /// * `password` - The plaintext password to verify.
    /// * `hashed_password` - The hashed password to compare against.
    ///
    /// # Returns
    ///
    /// * `Ok(true)` if the password matches the hash.
    /// * `Ok(false)` if the password does not match.
    /// * `Err(AuthError)` if verification fails.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let is_valid = manager.verify_password("my_password", &hashed).await?;
    /// ```
    async fn verify_password(
        &self,
        password: &str,
        hashed_password: &str,
    ) -> Result<bool, AuthError>;
}
