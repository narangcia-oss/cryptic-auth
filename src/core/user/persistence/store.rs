use super::{in_memory::InMemoryUserRepo, traits::UserRepository};
use crate::core::user::User;
use async_trait::async_trait;

#[cfg(feature = "postgres")]
use crate::postgres::PgUserRepo;

/// `PersistentUsers` is an enum that abstracts over different user repository backends.
///
/// This allows the application to switch between various persistence mechanisms for user data,
/// such as in-memory storage (for testing or ephemeral use) and a PostgreSQL database (for production).
///
/// # Variants
/// - `InMemory`: Stores users in memory. Useful for testing or non-persistent scenarios.
/// - `PostgresDatabase`: Stores users in a PostgreSQL database. Enabled with the `postgres` feature.
///
/// Additional backends (e.g., file system) can be added as needed.
#[derive(Debug)]
pub enum PersistentUsers {
    /// In-memory user repository. Fast, non-persistent, and ideal for tests or temporary data.
    InMemory(InMemoryUserRepo),
    /// PostgreSQL-backed user repository. Requires the `postgres` feature.
    #[cfg(feature = "postgres")]
    PostgresDatabase(PgUserRepo),
    // FileSystem(FsUserRepo),
}

impl PersistentUsers {
    /// Creates a new `PersistentUsers` instance backed by an in-memory repository.
    ///
    /// # Returns
    ///
    /// A `PersistentUsers::InMemory` variant with a fresh in-memory user repository.
    pub fn in_memory() -> Self {
        PersistentUsers::InMemory(InMemoryUserRepo::new())
    }

    /// Creates a new `PersistentUsers` instance backed by a PostgreSQL repository.
    ///
    /// # Parameters
    /// - `repo`: The PostgreSQL user repository to use.
    ///
    /// # Returns
    ///
    /// A `PersistentUsers::PostgresDatabase` variant wrapping the provided repository.
    #[cfg(feature = "postgres")]
    pub fn postgres_database(repo: PgUserRepo) -> Self {
        PersistentUsers::PostgresDatabase(repo)
    }
}

/// Implements the `UserRepository` trait for `PersistentUsers`,
/// delegating all operations to the selected backend.
///
/// This allows seamless switching between different persistence mechanisms
/// without changing the business logic that depends on `UserRepository`.
#[async_trait]
impl UserRepository for PersistentUsers {
    /// Adds a new user to the repository.
    ///
    /// Delegates to the underlying backend implementation.
    ///
    /// # Arguments
    /// * `user` - The user to add.
    ///
    /// # Returns
    ///
    /// `Ok(User)` if the user was added successfully, or an `AuthError` otherwise.
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError> {
        match self {
            PersistentUsers::InMemory(repo) => repo.add_user(user).await,
            #[cfg(feature = "postgres")]
            PersistentUsers::PostgresDatabase(repo) => repo.add_user(user).await,
        }
    }

    /// Retrieves a user by their unique ID.
    ///
    /// Delegates to the underlying backend implementation.
    ///
    /// # Arguments
    /// * `id` - The unique identifier of the user.
    ///
    /// # Returns
    ///
    /// `Some(User)` if found, or `None` if no user with the given ID exists.
    async fn get_user_by_id(&self, id: &str) -> Option<User> {
        match self {
            PersistentUsers::InMemory(repo) => repo.get_user_by_id(id).await,
            #[cfg(feature = "postgres")]
            PersistentUsers::PostgresDatabase(repo) => repo.get_user_by_id(id).await,
        }
    }

    /// Retrieves a user by a unique identifier (e.g., username or email).
    ///
    /// Delegates to the underlying backend implementation.
    ///
    /// # Arguments
    /// * `identifier` - The unique identifier (such as username or email).
    ///
    /// # Returns
    ///
    /// `Some(User)` if found, or `None` if no user with the given identifier exists.
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        match self {
            PersistentUsers::InMemory(repo) => repo.get_user_by_identifier(identifier).await,
            #[cfg(feature = "postgres")]
            PersistentUsers::PostgresDatabase(repo) => {
                repo.get_user_by_identifier(identifier).await
            }
        }
    }

    /// Updates an existing user in the repository.
    ///
    /// Delegates to the underlying backend implementation.
    ///
    /// # Arguments
    /// * `user` - The user with updated information.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the update was successful, or an `AuthError` otherwise.
    async fn update_user(&self, user: &User) -> Result<(), crate::error::AuthError> {
        match self {
            PersistentUsers::InMemory(repo) => repo.update_user(user).await,
            #[cfg(feature = "postgres")]
            PersistentUsers::PostgresDatabase(repo) => repo.update_user(user).await,
        }
    }

    /// Deletes a user from the repository by their unique ID.
    ///
    /// Delegates to the underlying backend implementation.
    ///
    /// # Arguments
    /// * `id` - The unique identifier of the user to delete.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the user was deleted successfully, or an `AuthError` otherwise.
    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError> {
        match self {
            PersistentUsers::InMemory(repo) => repo.delete_user(id).await,
            #[cfg(feature = "postgres")]
            PersistentUsers::PostgresDatabase(repo) => repo.delete_user(id).await,
        }
    }

    /// Retrieves a user by their OAuth provider and provider user ID.
    ///
    /// Delegates to the underlying backend implementation.
    ///
    /// # Arguments
    /// * `provider` - The OAuth2 provider.
    /// * `provider_user_id` - The user ID from the OAuth provider.
    ///
    /// # Returns
    ///
    /// `Some(User)` if found, or `None` if no user with the given OAuth credentials exists.
    async fn get_user_by_oauth_id(
        &self,
        provider: crate::core::oauth::store::OAuth2Provider,
        provider_user_id: &str,
    ) -> Option<User> {
        match self {
            PersistentUsers::InMemory(repo) => {
                repo.get_user_by_oauth_id(provider, provider_user_id).await
            }
            #[cfg(feature = "postgres")]
            PersistentUsers::PostgresDatabase(repo) => {
                repo.get_user_by_oauth_id(provider, provider_user_id).await
            }
        }
    }
}
