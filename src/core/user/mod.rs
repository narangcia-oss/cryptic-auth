//! This module defines data structures for users
//! and traits for persistence operations.

use crate::core::credentials::{Credentials, PlainPassword};

#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: String,
    pub credentials: Credentials,
}

impl User {
    /// Creates a new user with already hashed credentials
    pub fn new(id: String, credentials: Credentials) -> Self {
        Self { id, credentials }
    }

    /// Creates a user with a plaintext password (to be hashed)
    pub async fn with_plain_password(
        manager: &(dyn crate::core::password::SecurePasswordManager + Send + Sync),
        id: String,
        identifier: String,
        plain_password: PlainPassword,
    ) -> Result<Self, crate::error::AuthError> {
        let credentials =
            Credentials::from_plain_password(manager, identifier, plain_password).await?;

        Ok(Self { id, credentials })
    }
}

pub mod persistence;
