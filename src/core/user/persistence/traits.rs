/// Traits and abstractions for user persistence operations.
use crate::core::user::User;
use async_trait::async_trait;

/// An abstraction for user persistence, allowing async CRUD operations on users.
///
/// Implementors of this trait provide mechanisms to add, retrieve, update, and delete users
/// in a persistent store (e.g., database, in-memory, etc). All methods are asynchronous and
/// return results suitable for error handling in authentication contexts.
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Adds a new user to the repository.
    ///
    /// # Arguments
    /// * `user` - The user entity to be added.
    ///
    /// # Returns
    /// * `Ok(User)` - The newly created user (may include generated fields like id).
    /// * `Err(AuthError)` - If the user could not be added (e.g., duplicate, DB error).
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError>;

    /// Retrieves a user by their unique id.
    ///
    /// # Arguments
    /// * `id` - The unique identifier of the user.
    ///
    /// # Returns
    /// * `Some(User)` - The user if found.
    /// * `None` - If no user exists with the given id.
    async fn get_user_by_id(&self, id: &str) -> Option<User>;

    /// Retrieves a user by a unique identifier (e.g., username or email).
    ///
    /// # Arguments
    /// * `identifier` - The unique identifier (such as username or email).
    ///
    /// # Returns
    /// * `Some(User)` - The user if found.
    /// * `None` - If no user exists with the given identifier.
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User>;

    /// Updates an existing user in the repository.
    ///
    /// # Arguments
    /// * `user` - The user entity with updated fields.
    ///
    /// # Returns
    /// * `Ok(())` - If the update was successful.
    /// * `Err(AuthError)` - If the update failed (e.g., user not found, DB error).
    async fn update_user(&self, user: User) -> Result<(), crate::error::AuthError>;

    /// Deletes a user from the repository by their id.
    ///
    /// # Arguments
    /// * `id` - The unique identifier of the user to delete.
    ///
    /// # Returns
    /// * `Ok(())` - If the user was successfully deleted.
    /// * `Err(AuthError)` - If the deletion failed (e.g., user not found, DB error).
    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError>;
}
