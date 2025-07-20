use async_trait::async_trait;

use crate::core::user::User;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError>;
    async fn get_user_by_id(&self, id: &str) -> Option<User>;
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User>;
    async fn update_user(&self, user: User) -> Result<(), crate::error::AuthError>;
    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError>;
}
