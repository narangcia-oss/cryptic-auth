use crate::core::hash::{Argon2Hasher, salt::generate_secure_salt};
use crate::error::AuthError;
use crate::core::password::manager::SecurePasswordManager;

pub struct Argon2PasswordManager {
    hasher: Argon2Hasher,
}

impl Argon2PasswordManager {
    pub fn new() -> Self {
        Self {
            hasher: Argon2Hasher::new(),
        }
    }
}

#[async_trait::async_trait]
impl SecurePasswordManager for Argon2PasswordManager {
    async fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        if password.is_empty() {
            return Err(AuthError::InvalidPassword("Password cannot be empty".to_string()));
        }
        let hash = self.hasher.hash(password.as_bytes(), None)
            .map_err(|e| AuthError::HashingError(format!("Hashing error: {e}")))?;
        Ok(hash)
    }

    async fn verify_password(&self, password: &str, hashed_password: &str) -> Result<bool, AuthError> {
        if password.is_empty() || hashed_password.is_empty() {
            return Ok(false);
        }
        let valid = self.hasher.verify(password.as_bytes(), hashed_password)
            .map_err(|e| AuthError::VerificationError(format!("Verification error: {e}")))?;
        Ok(valid)
    }
}
