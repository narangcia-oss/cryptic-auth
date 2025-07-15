//! This module contains the password manager trait definition.

use crate::error::AuthError;

#[async_trait::async_trait]
pub trait SecurePasswordManager {
    async fn hash_password(&self, password: &str) -> Result<String, AuthError>;

    async fn verify_password(
        &self,
        password: &str,
        hashed_password: &str,
    ) -> Result<bool, AuthError>;
}