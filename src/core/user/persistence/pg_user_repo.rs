use async_trait::async_trait;

#[cfg(feature = "sqlx")]
use crate::{core::user::User, error::AuthError};

#[cfg(feature = "sqlx")]
#[derive(Debug)]
pub struct PgUserRepo {
    pool: sqlx::PgPool,
}

#[cfg(feature = "sqlx")]
impl PgUserRepo {
    pub async fn new(pool: sqlx::PgPool) -> Result<Self, String> {
        // Optionally run migrations or schema validation here
        // sqlx::migrate!("./migrations").run(&pool).await.map_err(|e| e.to_string())?;
        Ok(Self { pool })
    }
}

#[cfg(feature = "sqlx")]
#[async_trait]
impl super::traits::UserRepository for PgUserRepo {
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError> {
        Err(AuthError::NotImplemented(format!("add_user: {user}")))
    }
    async fn get_user_by_id(&self, id: &str) -> Option<User> {
        // Use sqlx to fetch user by id (stub)
        None
    }
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        // Use sqlx to fetch user by identifier (stub)
        None
    }
    async fn update_user(&self, user: User) -> Result<(), crate::error::AuthError> {
        // Use sqlx to update user (stub)
        Err(AuthError::NotImplemented(format!("update_user: {user}")))
    }
    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError> {
        // Use sqlx to delete user (stub)
        Err(AuthError::NotImplemented(format!("delete_user: {id}")))
    }
}
