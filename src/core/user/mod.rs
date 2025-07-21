//! User data structures and persistence traits.
//!
//! This module provides the [`User`] struct, which encapsulates user identity and credentials,
//! as well as methods for user creation with both hashed and plaintext passwords. It also
//! re-exports the [`persistence`] submodule, which defines traits and types for user persistence
//! operations (e.g., repositories).
//!
//! # Examples
//!
//! Creating a user with already hashed credentials:
//! ```rust
//! use cryptic::core::user::User;
//! use cryptic::core::credentials::Credentials;
//! let credentials = Credentials::default();
//! let user = User::new("user-id".to_string(), credentials);
//! ```
//!
//! Creating a user with a plaintext password (async):
//! ```ignore
//! use cryptic::core::user::User;
//! use cryptic::core::credentials::PlainPassword;
//! # async fn example(manager: &impl cryptic::core::password::SecurePasswordManager) {
//! let user = User::with_plain_password(
//!     manager,
//!     "user-id".to_string(),
//!     "username".to_string(),
//!     PlainPassword::from("password123"),
//! ).await.unwrap();
//! # }
//! ```

use crate::core::credentials::{Credentials, PlainPassword};
use crate::core::oauth::store::{OAuth2Provider, OAuth2UserInfo};
use std::collections::HashMap;

/// Represents a user in the authentication system.
///
/// The `User` struct contains a unique identifier and associated credentials.
/// The credentials include the user's identifier (e.g., username or email) and password hash.
#[derive(Debug, Clone, Default)]
pub struct User {
    /// Unique identifier for the user (preferably a UUID).
    pub id: String,
    /// User credentials, including hashed password and identifier.
    pub credentials: Option<Credentials>,
    /// OAuth2 accounts linked to this user
    pub oauth_accounts: HashMap<OAuth2Provider, OAuth2UserInfo>,
    /// Account creation timestamp
    pub created_at: chrono::NaiveDateTime,
    /// Last updated timestamp
    pub updated_at: chrono::NaiveDateTime,
}

impl User {
    /// Creates a new user with already hashed credentials.
    ///
    /// # Arguments
    /// * `id` - Unique identifier for the user (e.g., UUID).
    /// * `credentials` - User credentials, including hashed password and identifier.
    ///
    /// # Returns
    /// A new [`User`] instance.
    pub fn new(id: String, credentials: Credentials) -> Self {
        let now = chrono::Utc::now().naive_utc();
        Self {
            id,
            credentials: Some(credentials),
            oauth_accounts: HashMap::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Creates a user from a plaintext password, hashing it using the provided password manager.
    ///
    /// # Arguments
    /// * `manager` - Reference to a type implementing [`SecurePasswordManager`] for hashing passwords.
    /// * `id` - Unique identifier for the user (e.g., UUID).
    /// * `identifier` - User identifier (e.g., username or email).
    /// * `plain_password` - The user's plaintext password.
    ///
    /// # Returns
    /// * `Ok(User)` if the password was hashed and the user was created successfully.
    /// * `Err(AuthError)` if password hashing or credential creation fails.
    ///
    /// # Errors
    /// Returns [`AuthError`] if password hashing or credential creation fails.
    ///
    /// # Examples
    /// ```ignore
    /// # use cryptic::core::user::User;
    /// # use cryptic::core::credentials::PlainPassword;
    /// # async fn example(manager: &impl cryptic::core::password::SecurePasswordManager) {
    /// let user = User::with_plain_password(
    ///     manager,
    ///     "user-id".to_string(),
    ///     "username".to_string(),
    ///     PlainPassword::from("password123"),
    /// ).await.unwrap();
    /// # }
    /// ```
    pub async fn with_plain_password(
        manager: &(dyn crate::core::password::SecurePasswordManager + Send + Sync),
        id: String,
        identifier: String,
        plain_password: PlainPassword,
    ) -> Result<Self, crate::error::AuthError> {
        let credentials =
            Credentials::from_plain_password(manager, id.clone(), identifier, plain_password)
                .await?;

        Ok(Self {
            id,
            credentials: Some(credentials),
            oauth_accounts: HashMap::new(),
            created_at: chrono::Utc::now().naive_utc(),
            updated_at: chrono::Utc::now().naive_utc(),
        })
    }
}

/// Persistence traits and types for user storage and retrieval.
pub mod persistence;
