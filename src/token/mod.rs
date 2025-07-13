// src/token/mod.rs - Les Fragments de Destin des Tokens

//! Ce module gère la création, la validation et le rafraîchissement des tokens d'authentification.

use crate::error::AuthError;

/// Représente une paire de tokens (accès et rafraîchissement).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

/// Trait pour abstraire les opérations de token.
#[async_trait::async_trait]
pub trait TokenService {
    /// Génère une nouvelle paire de tokens pour un utilisateur donné.
    async fn generate_token_pair(
        &self,
        user_id: &str,
        user_roles: &[String],
    ) -> Result<TokenPair, AuthError>;
    /// Valide un token d'accès et extrait ses revendications.
    async fn validate_access_token<
        C: serde::de::DeserializeOwned + crate::token::claims::Claims + Send,
    >(
        &self,
        token: &str,
    ) -> Result<C, AuthError>;
    /// Rafraîchit un token d'accès en utilisant un token de rafraîchissement.
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError>;
}

/// Les revendications (claims) par défaut pour les JWT.
pub mod claims;
