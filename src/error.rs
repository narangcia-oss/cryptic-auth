use thiserror::Error;

/// All possible errors that can occur within the authentication crate.
///
/// This enum is used throughout the crate to represent error conditions that may arise
/// during authentication, user management, password handling, token operations, and more.
/// Each variant is documented to clarify the context in which it is used.

#[derive(Debug, Error)]
pub enum AuthError {
    /// Returned when the provided credentials are invalid (e.g., wrong password or username).
    #[error("Invalid credentials provided.")]
    InvalidCredentials,

    /// Returned when a user cannot be found in the data store.
    #[error("User not found.")]
    UserNotFound,

    /// Returned when attempting to create a user that already exists.
    #[error("User already exists.")]
    UserAlreadyExists,

    /// Returned when password hashing fails.
    /// Contains the underlying error message.
    #[error("Password hashing failed: {0}")]
    HashingError(String),

    /// Returned when password verification fails.
    /// Contains the underlying error message.
    #[error("Password verification failed: {0}")]
    PasswordVerificationError(String),

    /// Returned when there is a configuration error in the authentication system.
    /// Contains a description of the configuration issue.
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Returned when a service required for authentication is unavailable.
    /// Contains a description of the service issue.
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),

    /// Returned when a feature is not yet implemented.
    /// Contains a description of the missing feature.
    #[error("Feature not implemented yet: {0}")]
    NotImplemented(String),

    /// Returned when input data is invalid or malformed.
    /// Contains a description of the invalid input.
    #[error("Invalid input data: {0}")]
    InvalidInput(String),

    /// Returned when a password does not meet policy requirements or is otherwise invalid.
    /// Contains a description of the password issue.
    #[error("Invalid password: {0}")]
    InvalidPassword(String),

    /// Returned when a verification process fails (e.g., email or token verification).
    /// Contains a description of the verification error.
    #[error("Verification error: {0}")]
    VerificationError(String),

    /// Returned when a token (such as a JWT) has expired and is no longer valid.
    #[error("Token expired")]
    TokenExpired,

    /// Returned when token generation fails.
    /// Contains a description of the generation error.
    #[error("Token generation failed: {0}")]
    TokenGeneration(String),

    /// Returned when token validation fails.
    /// Contains a description of the validation error.
    #[error("Token validation failed: {0}")]
    TokenValidation(String),

    /// Returned when a token is invalid (malformed, tampered, or otherwise unusable).
    /// Contains a description of the invalid token.
    #[error("InvalidToken: {0}")]
    InvalidToken(String),

    /// Returned when the password manager component is missing or unavailable.
    #[error("Missing password manager")]
    MissingPasswordManager,

    /// Returned when the persistent user manager component is missing or unavailable.
    #[error("Missing persistent user manager")]
    MissingPersistentUserManager,

    /// Returned when the token manager component is missing or unavailable.
    #[error("Missing token manager")]
    MissingTokenManager,

    /// Returned when a database error occurs (only available with the `postgres` feature).
    /// Contains a description of the database error.
    #[cfg(feature = "postgres")]
    #[error("Database error: {0}")]
    DatabaseError(String),
}
