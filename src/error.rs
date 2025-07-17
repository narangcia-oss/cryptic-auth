use thiserror::Error;

/// Represents all errors that can occur within the authentication crate.
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
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
    #[error("Feature not implemented yet: {0}")]
    NotImplemented(String),
    #[error("Invalid input data: {0}")]
    InvalidInput(String),
    #[error("Invalid password: {0}")]
    InvalidPassword(String),
    #[error("Verification error: {0}")]
    VerificationError(String),
    #[error("Token expired")]
    TokenExpired,
    #[error("Token generation failed: {0}")]
    TokenGeneration(String),
    #[error("Token validation failed: {0}")]
    TokenValidation(String),
    #[error("InvalidToken: {0}")]
    InvalidToken(String),
    #[error("MissingPasswordManager")]
    MissingPasswordManager,
    #[error("MissingPersistentUserManager")]
    MissingPersistentUserManager,
}
