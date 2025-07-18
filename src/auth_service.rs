//! This module contains the high-level logic for user authentication,
//! acting as the central point of the crate's interactions.

use std::sync::Arc;

use crate::{core::user::User, error::AuthError};

/// The main structure of the authentication service.
/// It aggregates the necessary dependencies to perform operations.
pub struct AuthService {
    pub vars: Arc<crate::core::vars::AuthServiceVariables>,
    pub password_manager: Box<dyn crate::core::password::SecurePasswordManager + Send + Sync>,
    pub persistent_users_manager:
        Box<dyn crate::core::user::persistence::UserRepository + Send + Sync>,
    pub token_manager: Box<dyn crate::core::token::TokenService + Send + Sync>,
}

impl Default for AuthService {
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
        let pwd_manager = password_manager.ok_or(AuthError::MissingPasswordManager)?;
        let pum = persistent_users_manager.ok_or(AuthError::MissingPersistentUserManager)?;
        let tk_manager = token_manager.ok_or(AuthError::MissingTokenManager)?;

        Ok(AuthService {
            vars,
            password_manager: pwd_manager,
            persistent_users_manager: pum,
            token_manager: tk_manager,
        })
    }

    /// Attempts to register a new user.
    pub async fn signup(&self, user: User) -> Result<(), AuthError> {
        self.persistent_users_manager
            .add_user(user)
            .map_err(|e| AuthError::NotImplemented(format!("signup: {e}")))
    }

    /// Attempts to log in a user by verifying their credentials.
    /// Returns a user if login is successful, or an error if authentication fails.
    pub async fn login_with_credentials(
        &self,
        identifier: &str,
        plain_password: &str,
    ) -> Result<User, AuthError> {
        // Find user by identifier (assuming identifier is stored in credentials.identifier)
        let stored_user = self
            .persistent_users_manager
            .get_user_by_identifier(identifier)
            .ok_or(AuthError::InvalidCredentials)?;

        // Verify the password using the password manager from the service
        let is_valid = self
            .password_manager
            .verify_password(plain_password, &stored_user.credentials.password_hash)
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

    /// Generates a new token pair for a given user ID.
    pub async fn get_tokens(&self, id: String) -> Result<crate::core::token::TokenPair, AuthError> {
        self.token_manager.generate_token_pair(&id).await
    }

    /// Validates an access token and returns the claims.
    pub async fn validate_access_token(
        &self,
        token: &str,
    ) -> Result<Box<dyn crate::core::token::claims::Claims + Send + Sync>, AuthError> {
        self.token_manager.validate_access_token(token).await
    }

    /// Refreshes an access token using a refresh token.
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
    ) -> Result<crate::core::token::TokenPair, AuthError> {
        self.token_manager.refresh_access_token(refresh_token).await
    }

    /// Validates a token and extracts the user ID from it.
    pub async fn get_user_id_from_token(&self, token: &str) -> Result<String, AuthError> {
        let claims = self.validate_access_token(token).await?;
        Ok(claims.get_subject().to_string())
    }

    /// Checks if a token is expired by validating it.
    pub async fn is_token_expired(&self, token: &str) -> bool {
        self.validate_access_token(token).await.is_err()
    }

    /// Complete login flow that returns both user and tokens.
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

    /// Validates a token and retrieves the associated user.
    pub async fn get_user_from_token(&self, token: &str) -> Result<User, AuthError> {
        let user_id = self.get_user_id_from_token(token).await?;
        self.persistent_users_manager
            .get_user_by_id(&user_id)
            .ok_or(AuthError::UserNotFound)
    }
}
