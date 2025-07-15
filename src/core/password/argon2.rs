//! This module contains the Argon2 password manager implementation.

use crate::error::AuthError;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier},
};

use super::manager::SecurePasswordManager;

#[derive(Default)]
pub struct Argon2PasswordManager {
    hasher: Argon2<'static>,
}

impl Argon2PasswordManager {
    pub fn new() -> Self {
        Self {
            hasher: Argon2::default(),
        }
    }
}

#[async_trait::async_trait]
impl SecurePasswordManager for Argon2PasswordManager {
    async fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        if password.is_empty() {
            return Err(AuthError::InvalidPassword(
                "Password cannot be empty".to_string(),
            ));
        }

        let salt = match super::salt::generate_secure_salt() {
            Ok(salt) => salt,
            Err(e) => {
                log::error!("Error generating salt: {e}");
                return Err(AuthError::HashingError(format!(
                    "Error generating salt: {e}",
                )));
            }
        };

        let password_hash = self
            .hasher
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::HashingError(format!("Hashing error: {e}")))?;

        Ok(password_hash.to_string())
    }

    async fn verify_password(
        &self,
        password: &str,
        hashed_password: &str,
    ) -> Result<bool, AuthError> {
        if password.is_empty() || hashed_password.is_empty() {
            return Ok(false);
        }

        let parsed_hash = PasswordHash::new(hashed_password)
            .map_err(|e| AuthError::VerificationError(format!("Invalid hash: {e}")))?;

        match self
            .hasher
            .verify_password(password.as_bytes(), &parsed_hash)
        {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(AuthError::VerificationError(format!(
                "Verification error: {e}",
            ))),
        }
    }
}
