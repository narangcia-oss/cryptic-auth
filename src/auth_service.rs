//! # Authentication Service Module
//!
//! This module provides the high-level logic for user authentication, acting as the central point of the crate's interactions.
//! It exposes the [`AuthService`] struct, which aggregates all necessary dependencies and provides methods for user registration,
//! login, token management, and user retrieval. The service is designed to be flexible and extensible, allowing for custom
//! password managers, user repositories, and token services.
//!
//! ## Features
//! - User registration and login
//! - Password verification and management
//! - Token generation, validation, and refresh
//! - User retrieval from tokens
//! - Extensible via dependency injection

use std::sync::Arc;

use crate::{core::user::User, error::AuthError};

/// The main structure of the authentication service.
/// It aggregates the necessary dependencies to perform operations.
/// The main structure of the authentication service.
///
/// `AuthService` aggregates the necessary dependencies to perform authentication operations, such as user registration,
/// login, token management, and user retrieval. It is designed to be flexible and allows for custom implementations of
/// password managers, user repositories, and token services.
pub struct AuthService {
    /// Shared configuration and variables for the authentication service.
    pub vars: Arc<crate::core::vars::AuthServiceVariables>,
    /// The password manager responsible for password hashing and verification.
    pub password_manager: Box<dyn crate::core::password::SecurePasswordManager + Send + Sync>,
    /// The user repository for persistent user management (e.g., database or in-memory store).
    pub persistent_users_manager:
        Box<dyn crate::core::user::persistence::UserRepository + Send + Sync>,
    /// The token manager responsible for generating and validating authentication tokens.
    pub token_manager: Box<dyn crate::core::token::TokenService + Send + Sync>,
}

impl Default for AuthService {
    /// Creates a default [`AuthService`] instance using default variables, Argon2 password manager,
    /// in-memory user repository, and JWT token service.
    fn default() -> Self {
        let vars = Arc::new(crate::core::vars::AuthServiceVariables::default());
        Self {
            vars: vars.clone(),
            password_manager: Box::new(crate::core::password::Argon2PasswordManager::default()),
            persistent_users_manager: Box::new(
                crate::core::user::persistence::InMemoryUserRepo::new(),
            ),
            token_manager: Box::new(crate::core::token::jwt::JwtTokenService::new(
                &vars.secret_key,
                vars.token_expiration,
                vars.refresh_token_expiration,
            )),
        }
    }
}

impl AuthService {
    /// Constructs a new [`AuthService`] with the provided dependencies.
    ///
    /// # Arguments
    /// * `vars` - Shared configuration and variables for the authentication service.
    /// * `password_manager` - Optional custom password manager. If `None`, uses Argon2 by default.
    /// * `persistent_users_manager` - Optional custom user repository. If `None`, uses in-memory repository by default.
    /// * `token_manager` - Optional custom token service. If `None`, uses JWT token service by default.
    ///
    /// # Returns
    /// Returns an [`AuthService`] instance or an [`AuthError`] if construction fails.
    pub fn new(
        vars: Arc<crate::core::vars::AuthServiceVariables>,
        password_manager: Option<
            Box<dyn crate::core::password::SecurePasswordManager + Send + Sync>,
        >,
        persistent_users_manager: Option<
            Box<dyn crate::core::user::persistence::UserRepository + Send + Sync>,
        >,
        token_manager: Option<Box<dyn crate::core::token::TokenService + Send + Sync>>,
    ) -> Result<Self, AuthError> {
        let pwd_manager = match password_manager {
            Some(manager) => manager,
            None => Box::new(crate::core::password::Argon2PasswordManager::default()),
        };
        let pum = match persistent_users_manager {
            Some(manager) => manager,
            None => Box::new(crate::core::user::persistence::InMemoryUserRepo::new()),
        };
        let tk_manager = match token_manager {
            Some(manager) => manager,
            None => Box::new(crate::core::token::jwt::JwtTokenService::new(
                &vars.secret_key,
                vars.token_expiration,
                vars.refresh_token_expiration,
            )),
        };

        Ok(AuthService {
            vars,
            password_manager: pwd_manager,
            persistent_users_manager: pum,
            token_manager: tk_manager,
        })
    }

    /// Registers a new user in the system.
    ///
    /// # Arguments
    /// * `user` - The [`User`] object to register.
    ///
    /// # Returns
    /// Returns `Ok(())` if registration is successful, or an [`AuthError`] if registration fails.
    pub async fn signup(&self, user: User) -> Result<(), AuthError> {
        self.persistent_users_manager
            .add_user(user)
            .await
            .map(|_user| ()) // Discard the returned User, return ()
            .map_err(|e| AuthError::NotImplemented(format!("signup: {e}")))
    }

    /// Attempts to log in a user by verifying their credentials.
    ///
    /// # Arguments
    /// * `identifier` - The user identifier (e.g., username or email).
    /// * `plain_password` - The user's plain text password.
    ///
    /// # Returns
    /// Returns the [`User`] if login is successful, or an [`AuthError`] if authentication fails.
    pub async fn login_with_credentials(
        &self,
        identifier: &str,
        plain_password: &str,
    ) -> Result<User, AuthError> {
        // Find user by identifier (assuming identifier is stored in credentials.identifier)
        let stored_user = self
            .persistent_users_manager
            .get_user_by_identifier(identifier)
            .await
            .ok_or(AuthError::InvalidCredentials)?;

        // Verify the password using the password manager from the service
        let credentials = stored_user
            .credentials
            .as_ref()
            .ok_or(AuthError::InvalidCredentials)?;
            
        let is_valid = self
            .password_manager
            .verify_password(plain_password, &credentials.password_hash)
            .await
            .map_err(|e| {
                AuthError::PasswordVerificationError(format!("Password verification failed: {e}"))
            })?;

        if is_valid {
            Ok(stored_user)
        } else {
            Err(AuthError::InvalidCredentials)
        }
    }

    /// Generates a new token pair (access and refresh tokens) for a given user ID.
    ///
    /// # Arguments
    /// * `id` - The user ID for which to generate tokens.
    ///
    /// # Returns
    /// Returns a [`TokenPair`] containing access and refresh tokens, or an [`AuthError`] if generation fails.
    pub async fn get_tokens(&self, id: String) -> Result<crate::core::token::TokenPair, AuthError> {
        self.token_manager.generate_token_pair(&id).await
    }

    /// Validates an access token and returns the associated claims.
    ///
    /// # Arguments
    /// * `token` - The access token to validate.
    ///
    /// # Returns
    /// Returns the token claims if valid, or an [`AuthError`] if validation fails.
    pub async fn validate_access_token(
        &self,
        token: &str,
    ) -> Result<Box<dyn crate::core::token::claims::Claims + Send + Sync>, AuthError> {
        self.token_manager.validate_access_token(token).await
    }

    /// Refreshes an access token using a valid refresh token.
    ///
    /// # Arguments
    /// * `refresh_token` - The refresh token to use for generating a new access token.
    ///
    /// # Returns
    /// Returns a new [`TokenPair`] if the refresh token is valid, or an [`AuthError`] if refresh fails.
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<crate::core::token::TokenPair, AuthError> {
        self.token_manager.refresh_access_token(refresh_token).await
    }

    /// Validates a token and extracts the user ID (subject) from it.
    ///
    /// # Arguments
    /// * `token` - The token to validate and extract the user ID from.
    ///
    /// # Returns
    /// Returns the user ID as a `String` if the token is valid, or an [`AuthError`] if validation fails.
    pub async fn get_user_id_from_token(&self, token: &str) -> Result<String, AuthError> {
        let claims = self.validate_access_token(token).await?;
        Ok(claims.get_subject().to_string())
    }

    /// Checks if a token is expired by attempting to validate it.
    ///
    /// # Arguments
    /// * `token` - The token to check for expiration.
    ///
    /// # Returns
    /// Returns `true` if the token is expired or invalid, `false` otherwise.
    pub async fn is_token_expired(&self, token: &str) -> bool {
        self.validate_access_token(token).await.is_err()
    }

    /// Complete login flow that returns both the user and a new token pair.
    ///
    /// # Arguments
    /// * `identifier` - The user identifier (e.g., username or email).
    /// * `plain_password` - The user's plain text password.
    ///
    /// # Returns
    /// Returns a tuple of the [`User`] and a [`TokenPair`] if login is successful, or an [`AuthError`] if authentication fails.
    pub async fn login_with_credentials_and_tokens(
        &self,
        identifier: &str,
        plain_password: &str,
    ) -> Result<(User, crate::core::token::TokenPair), AuthError> {
        let user = self
            .login_with_credentials(identifier, plain_password)
            .await?;
        let tokens = self.get_tokens(user.id.clone()).await?;
        Ok((user, tokens))
    }

    /// Validates a token and retrieves the associated user from the repository.
    ///
    /// # Arguments
    /// * `token` - The token to validate and extract the user from.
    ///
    /// # Returns
    /// Returns the [`User`] if the token is valid and the user exists, or an [`AuthError`] otherwise.
    pub async fn get_user_from_token(&self, token: &str) -> Result<User, AuthError> {
        let user_id = self.get_user_id_from_token(token).await?;
        self.persistent_users_manager
            .get_user_by_id(&user_id)
            .await
            .ok_or(AuthError::UserNotFound)
    }
}
