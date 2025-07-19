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
impl crate::core::user::persistence::traits::UserRepository for PgUserRepo {
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError> {
        let _ = self.pool; // Suppress unused variable warning
        let _ = user; // Suppress unused variable warning
        Err(AuthError::NotImplemented(
            "add_user not implemented for PgUserRepo".to_string(),
        ))
    }
    async fn get_user_by_id(&self, id: &str) -> Option<User> {
        // Use sqlx to fetch user by id (stub)
        let _ = id; // Suppress unused variable warning
        None
    }
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        // Use sqlx to fetch user by identifier (stub)
        let _ = identifier; // Suppress unused variable warning
        None
    }
    async fn update_user(&self, user: User) -> Result<(), crate::error::AuthError> {
        // Use sqlx to update user (stub)
        let _ = user; // Suppress unused variable warning
        Err(AuthError::NotImplemented(
            "update_user not implemented for PgUserRepo".to_string(),
        ))
    }
    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError> {
        // Use sqlx to delete user (stub)
        let _ = id; // Suppress unused variable warning
        Err(AuthError::NotImplemented(
            "delete_user not implemented for PgUserRepo".to_string(),
        ))
    }
}
