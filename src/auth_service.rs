//! This module contains the high-level logic for user authentication,
//! acting as the central point of the crate's interactions.

use crate::{core::user::User, error::AuthError};

/// The main structure of the authentication service.
/// It aggregates the necessary dependencies to perform operations.
pub struct AuthService {
    pub password_manager: Box<dyn crate::core::password::SecurePasswordManager + Send + Sync>,
    pub persistent_users_manager:
        Box<dyn crate::core::user::persistence::UserRepository + Send + Sync>,
    pub token_manager: Box<dyn crate::core::token::TokenService + Send + Sync>,
}

impl Default for AuthService {
    fn default() -> Self {
        Self {
            password_manager: Box::new(crate::core::password::Argon2PasswordManager::default()),
            persistent_users_manager: Box::new(
                crate::core::user::persistence::InMemoryUserRepo::new(),
            ),
            token_manager: Box::new(crate::core::token::jwt::JwtTokenService::new(
                "e", 5000, 5000,
            )),
        }
    }
}

impl AuthService {
    pub fn new(
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
}
