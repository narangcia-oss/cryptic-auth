// src/auth_service.rs - The Grand Orchestrator of Authentication Operations

//! This module contains the high-level logic for user authentication,
//! acting as the central point of the crate's interactions.

use crate::{
    core::user::User,
    error::{AuthError, Z3AuthServiceError},
};

/// The main structure of the authentication service.
/// It aggregates the necessary dependencies to perform operations.
pub struct Z3AuthService {
    password_manager: Box<dyn crate::core::password::SecurePasswordManager + Send + Sync>,
    persistent_users_manager: Box<dyn crate::core::user::persistence::UserRepository + Send + Sync>,
}

impl Z3AuthService {
    pub fn new(
        password_manager: Option<
            Box<dyn crate::core::password::SecurePasswordManager + Send + Sync>,
        >,
        persistent_users_manager: Option<
            Box<dyn crate::core::user::persistence::UserRepository + Send + Sync>,
        >,
    ) -> Result<Self, Z3AuthServiceError> {
        let pwd_manager = password_manager.ok_or(Z3AuthServiceError::MissingPasswordManager)?;
        let pum =
            persistent_users_manager.ok_or(Z3AuthServiceError::MissingPersistentUserManager)?;

        Ok(Z3AuthService {
            password_manager: pwd_manager,
            persistent_users_manager: pum,
        })
    }

    /// Attempts to register a new user.
    pub async fn signup(&self, user: User) -> Result<(), AuthError> {
        self.persistent_users_manager
            .add_user(user)
            .map_err(|e| AuthError::NotImplemented(format!("signup: {e}")))
    }

    /// Attempts to log in a user by verifying their credentials.
    /// Returns Ok(()) if login is successful, or an error if authentication fails.
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

    pub async fn logout(&self, user_id: &str) -> Result<(), AuthError> {
        // Placeholder for logout logic
        Err(AuthError::NotImplemented(
            "logout not implemented".to_string(),
        ))
    }

    pub async fn refresh_token(&self, user_id: &str) -> Result<String, AuthError> {
        // Placeholder for token refresh logic
        Err(AuthError::NotImplemented(
            "refresh_token not implemented".to_string(),
        ))
    }

    pub async fn validate_token(&self, token: &str) -> Result<bool, AuthError> {
        // Placeholder for token validation logic
        Err(AuthError::NotImplemented(
            "validate_token not implemented".to_string(),
        ))
    }

    pub async fn create_token(&self, user_id: &str) -> Result<String, AuthError> {
        // Placeholder for token creation logic
        Err(AuthError::NotImplemented(
            "create_token not implemented".to_string(),
        ))
    }

    pub async fn change_password(
        &self,
        user_id: &str,
        new_password: &str,
    ) -> Result<(), AuthError> {
        // Placeholder for password change logic
        Err(AuthError::NotImplemented(
            "change_password not implemented".to_string(),
        ))
    }

    pub async fn verify_user(&self, user_id: &str) -> Result<bool, AuthError> {
        // Placeholder for user verification logic
        Err(AuthError::NotImplemented(
            "verify_user not implemented".to_string(),
        ))
    }
}
