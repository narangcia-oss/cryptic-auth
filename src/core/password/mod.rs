//! Ce module gère le hachage et la vérification sécurisée des mots de passe.

use crate::error::AuthError;

/// Trait pour abstraire le hachage et la vérification des mots de passe.
#[async_trait::async_trait]
pub trait PasswordHasher {
    /// Hashe un mot de passe donné.
    async fn hash_password(&self, password: &str) -> Result<String, AuthError>;
    /// Vérifie si un mot de passe clair correspond à un hachage donné.
    async fn verify_password(
        &self,
        password: &str,
        hashed_password: &str,
    ) -> Result<bool, AuthError>;
}
