//! This module defines data structures for user credentials
//! and related functionality.

pub mod plain_password;

pub use plain_password::PlainPassword;

#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub identifier: String,
    pub password_hash: String,
}

impl Credentials {
    /// Creates credentials with an already calculated hash
    pub fn new(identifier: String, password_hash: String) -> Self {
        Self {
            identifier,
            password_hash,
        }
    }

    /// Creates credentials by hashing a plaintext password
    pub async fn from_plain_password(
        manager: &(dyn crate::core::password::SecurePasswordManager + Send + Sync),
        identifier: String,
        plain_password: PlainPassword,
    ) -> Result<Self, crate::error::AuthError> {
        let password_hash = manager
            .hash_password(plain_password.as_str())
            .await
            .map_err(|e| crate::error::AuthError::HashingError(format!("Couldn't hash : {e}")))?;

        Ok(Self {
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
