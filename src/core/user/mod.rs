//! This module defines data structures for users
//! and traits for persistence operations.

use zeroize::{Zeroize, ZeroizeOnDrop}; // Imports the ZeroizeOnDrop trait

#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: String,
    pub credentials: Credentials,
}

/// Structure for credentials with memory protection
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub identifier: String,
    /// The hashed password - never in plaintext!
    pub password_hash: String,
}

/// Temporary structure for plaintext passwords
/// Automatically clears itself from memory
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PlainPassword(String);

impl PlainPassword {
    pub fn new(password: String) -> Self {
        Self(password)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Trait to abstract user persistence operations.
#[async_trait::async_trait]
pub trait UserRepository {
    async fn find_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<User>, crate::error::AuthError>;

    async fn create(&self, user: User) -> Result<User, crate::error::AuthError>;

    async fn update(&self, user: User) -> Result<User, crate::error::AuthError>;
}

impl User {
    /// Creates a new user with already hashed credentials
    pub fn new(id: String, credentials: Credentials) -> Self {
        Self { id, credentials }
    }

    /// Creates a user with a plaintext password (to be hashed)
    pub async fn with_plain_password(
        id: String,
        identifier: String,
        plain_password: PlainPassword,
    ) -> Result<Self, crate::error::AuthError> {
        let credentials = Credentials::from_plain_password(identifier, plain_password).await?;

        Ok(Self { id, credentials })
    }
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
        identifier: String,
        plain_password: PlainPassword,
    ) -> Result<Self, crate::error::AuthError> {
        let manager = crate::core::password::Argon2PasswordManager::new();
        let password_hash = super::password::SecurePasswordManager::hash_password(
            &manager,
            plain_password.as_str(),
        )
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
        plain_password: &PlainPassword,
    ) -> Result<bool, crate::error::AuthError> {
        let manager = crate::core::password::Argon2PasswordManager::new();
        super::password::SecurePasswordManager::verify_password(
            &manager,
            plain_password.as_str(),
            &self.password_hash,
        )
        .await
        .map_err(|e| crate::error::AuthError::VerificationError(format!("Couldn't verify : {e}")))
    }
}
