// src/error.rs - Le Miroir des Échecs Sécurisés

use thiserror::Error;

/// Représente toutes les erreurs qui peuvent survenir au sein de la crate d'authentification.
/// Inspiré par les défis que même la magie d'Ahri doit surmonter.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials provided.")]
    InvalidCredentials,
    #[error("User already exists.")]
    UserAlreadyExists,
    #[error("Password hashing failed: {0}")]
    HashingError(String),
    #[error("Password verification failed: {0}")]
    PasswordVerificationError(String),
    #[error("Token creation failed: {0}")]
    TokenCreationError(String),
    #[error("Token validation failed: {0}")]
    TokenValidationError(String),
    #[error("Token refresh failed: {0}")]
    TokenRefreshError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Service indisponible: {0}")]
    ServiceUnavailable(String),
    #[error("Feature not implemented yet: {0}")]
    NotImplemented(String),
    #[error("Invalid input data: {0}")]
    InvalidInput(String),
    #[error("Mot de passe invalide: {0}")]
    InvalidPassword(String),
    #[error("Erreur de vérification: {0}")]
    VerificationError(String),
}
