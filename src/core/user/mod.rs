//! Ce module définit les structures de données pour les utilisateurs
//! et les traits pour les opérations de persistance.

use zeroize::{Zeroize, ZeroizeOnDrop}; // Importe le trait ZeroizeOnDrop

#[derive(Debug, Clone, Default)]
pub struct User {
    pub id: String,
    pub credentials: Credentials,
}

/// Structure pour les credentials avec protection mémoire
#[derive(Debug, Clone, Default)]
pub struct Credentials {
    pub identifier: String,
    /// Le mot de passe hashé - jamais en clair !
    pub password_hash: String,
}

/// Structure temporaire pour les mots de passe en clair
/// Se nettoie automatiquement de la mémoire
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

/// Trait pour abstraire les opérations de persistance des utilisateurs.
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
    /// Crée un nouvel utilisateur avec des credentials déjà hashés
    pub fn new(id: String, credentials: Credentials) -> Self {
        Self { id, credentials }
    }

    /// Crée un utilisateur avec un mot de passe en clair (à hasher)
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
    /// Crée des credentials avec un hash déjà calculé
    pub fn new(identifier: String, password_hash: String) -> Self {
        Self {
            identifier,
            password_hash,
        }
    }

    /// Crée des credentials en hashant un mot de passe en clair
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

    /// Vérifie un mot de passe contre le hash stocké
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
