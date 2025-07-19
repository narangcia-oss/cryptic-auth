use async_trait::async_trait;

#[cfg(feature = "postgres")]
use crate::{core::user::User, error::AuthError};

#[cfg(feature = "postgres")]
#[derive(Debug)]
pub struct PgUserRepo {
    pool: sqlx::PgPool,
}

#[cfg(feature = "postgres")]
impl PgUserRepo {
    pub async fn new(pool: sqlx::PgPool) -> Result<Self, String> {
        // Optionally run migrations or schema validation here
        // sqlx::migrate!("./migrations").run(&pool).await.map_err(|e| e.to_string())?;
        Ok(Self { pool })
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl crate::core::user::persistence::traits::UserRepository for PgUserRepo {
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        // Insert into cryptic_users
        sqlx::query!("INSERT INTO cryptic_users (id) VALUES ($1)", user.id)
            .execute(&mut *tx)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Insert into cryptic_credentials
        sqlx::query!(
            "INSERT INTO cryptic_credentials (user_id, identifier, password_hash) VALUES ($1, $2, $3)",
            user.credentials.user_id,
            user.credentials.identifier,
            user.credentials.password_hash
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(user)
    }
    async fn get_user_by_id(&self, id: &str) -> Option<User> {
        let rec = sqlx::query!(
            r#"SELECT u.id, c.user_id, c.identifier, c.password_hash
                FROM cryptic_users u
                JOIN cryptic_credentials c ON u.id = c.user_id
                WHERE u.id = $1"#,
            id
        )
        .fetch_one(&self.pool)
        .await
        .ok()?;

        Some(User {
            id: rec.id,
            credentials: crate::core::credentials::Credentials {
                user_id: rec.user_id,
                identifier: rec.identifier,
                password_hash: rec.password_hash,
            },
        })
    }
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        let rec = sqlx::query!(
            r#"SELECT u.id, c.user_id, c.identifier, c.password_hash
                FROM cryptic_users u
                JOIN cryptic_credentials c ON u.id = c.user_id
                WHERE c.identifier = $1"#,
            identifier
        )
        .fetch_one(&self.pool)
        .await
        .ok()?;

        Some(User {
            id: rec.id,
            credentials: crate::core::credentials::Credentials {
                user_id: rec.user_id,
                identifier: rec.identifier,
                password_hash: rec.password_hash,
            },
        })
    }
    async fn update_user(&self, user: User) -> Result<(), crate::error::AuthError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        // Update credentials (identifier and password_hash)
        sqlx::query!(
            "UPDATE cryptic_credentials SET identifier = $1, password_hash = $2 WHERE user_id = $3",
            user.credentials.identifier,
            user.credentials.password_hash,
            user.credentials.user_id
        )
        .execute(&mut *tx)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        tx.commit()
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }
    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError> {
        sqlx::query!("DELETE FROM cryptic_users WHERE id = $1", id)
            .execute(&self.pool)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}
