//! This module defines data structures for user credentials
//! and related functionality.

pub mod plain_password;

pub use plain_password::PlainPassword;

#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub user_id: String,       // Unique identifier for the user (preferably UUID)
    pub identifier: String,    // Unique identifier for the user (preferably email or username)
    pub password_hash: String, // Hashed password
}

impl Credentials {
    /// Creates credentials with an already calculated hash
    pub fn new(user_id: String, identifier: String, password_hash: String) -> Self {
        Self {
            user_id,
            identifier,
            password_hash,
        }
    }

    /// Creates credentials by hashing a plaintext password
    pub async fn from_plain_password(
        manager: &(dyn crate::core::password::SecurePasswordManager + Send + Sync),
        user_id: String,
        identifier: String,
        plain_password: PlainPassword,
    ) -> Result<Self, crate::error::AuthError> {
        let password_hash = manager
            .hash_password(plain_password.as_str())
            .await
            .map_err(|e| crate::error::AuthError::HashingError(format!("Couldn't hash : {e}")))?;

        Ok(Self {
            user_id,
            identifier,
            password_hash,
        })
    }

    /// Verifies a password against the stored hash
    pub async fn verify_password(
        &self,
        manager: &(dyn crate::core::password::SecurePasswordManager + Send + Sync),
        plain_password: &PlainPassword,
    ) -> Result<bool, crate::error::AuthError> {
        manager
            .verify_password(plain_password.as_str(), &self.password_hash)
            .await
            .map_err(|e| {
                crate::error::AuthError::VerificationError(format!("Couldn't verify : {e}"))
            })
    }
}
