//! This module defines security policies and rules,
//! such as password complexity requirements.

use crate::error::AuthError;

/// Defines the requirements for a strong password.
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special_char: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special_char: true,
        }
    }
}

impl PasswordPolicy {
    /// Validates if a password meets the defined policy.
    pub fn validate_password(&self, password: &str) -> Result<(), AuthError> {
        if password.len() < self.min_length {
            return Err(AuthError::InvalidInput(format!(
                "Password must be at least {} characters long.",
                self.min_length
            )));
        }

        if self.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(AuthError::InvalidInput(
                "Password must contain at least one uppercase letter.".to_string(),
            ));
        }
        if self.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
            return Err(AuthError::InvalidInput(
                "Password must contain at least one lowercase letter.".to_string(),
            ));
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(AuthError::InvalidInput(
                "Password must contain at least one digit.".to_string(),
            ));
        }
        if self.require_special_char && !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
            return Err(AuthError::InvalidInput(
                "Password must contain at least one special character.".to_string(),
            ));
        }
        Ok(())
    }
}
