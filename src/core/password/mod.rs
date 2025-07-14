//! Ce module gère le hachage et la vérification sécurisée des mots de passe.

use crate::error::AuthError;
pub mod salt;
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier},
};

#[async_trait::async_trait]
pub trait SecurePasswordManager {
    async fn hash_password(&self, password: &str) -> Result<String, AuthError>;

    async fn verify_password(
        &self,
        password: &str,
        hashed_password: &str,
    ) -> Result<bool, AuthError>;
}

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

impl Default for Argon2PasswordManager {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SecurePasswordManager for Argon2PasswordManager {
    async fn hash_password(&self, password: &str) -> Result<String, AuthError> {
        if password.is_empty() {
            return Err(AuthError::InvalidPassword(
                "Le mot de passe ne peut pas être vide".to_string(),
            ));
        }

        let salt = match salt::generate_secure_salt() {
            Ok(salt) => salt,
            Err(e) => {
                log::error!("Erreur lors de la génération du salt : {e}");
                return Err(AuthError::HashingError(format!(
                    "Erreur lors de la génération du salt: {e}",
                )));
            }
        };

        let password_hash = self
            .hasher
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| AuthError::HashingError(format!("Erreur lors du hachage: {e}")))?;

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
            .map_err(|e| AuthError::VerificationError(format!("Hash invalide: {e}")))?;

        match self
            .hasher
            .verify_password(password.as_bytes(), &parsed_hash)
        {
            Ok(()) => Ok(true),
            Err(argon2::password_hash::Error::Password) => Ok(false),
            Err(e) => Err(AuthError::VerificationError(format!(
                "Erreur lors de la vérification: {e}",
            ))),
        }
    }
}
