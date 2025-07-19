use async_trait::async_trait;
use uuid::Uuid;

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
        // Convert String IDs to Uuid
        let user_id =
            Uuid::parse_str(&user.id).map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let cred_user_id = Uuid::parse_str(&user.credentials.user_id)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Insert into cryptic_users
        sqlx::query!("INSERT INTO cryptic_users (id) VALUES ($1)", user_id)
            .execute(&mut *conn)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Insert into cryptic_credentials
        sqlx::query!(
            "INSERT INTO cryptic_credentials (user_id, identifier, password_hash) VALUES ($1, $2, $3)",
            cred_user_id,
            user.credentials.identifier,
            user.credentials.password_hash
        )
        .execute(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        Ok(user)
    }
    async fn get_user_by_id(&self, id: &str) -> Option<User> {
        let uuid = Uuid::parse_str(id).ok()?;
        let mut conn = self.pool.acquire().await.ok()?;
        let rec = sqlx::query!(
            r#"SELECT u.id, c.user_id, c.identifier, c.password_hash
                FROM cryptic_users u
                JOIN cryptic_credentials c ON u.id = c.user_id
                WHERE u.id = $1"#,
            uuid
        )
        .fetch_one(&mut *conn)
        .await
        .ok()?;

        Some(User {
            id: rec.id.to_string(),
            credentials: crate::core::credentials::Credentials {
                user_id: rec.user_id.to_string(),
                identifier: rec.identifier,
                password_hash: rec.password_hash,
            },
        })
    }
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        let mut conn = self.pool.acquire().await.ok()?;
        let rec = sqlx::query!(
            r#"SELECT u.id, c.user_id, c.identifier, c.password_hash
                FROM cryptic_users u
                JOIN cryptic_credentials c ON u.id = c.user_id
                WHERE c.identifier = $1"#,
            identifier
        )
        .fetch_one(&mut *conn)
        .await
        .ok()?;

        Some(User {
            id: rec.id.to_string(),
            credentials: crate::core::credentials::Credentials {
                user_id: rec.user_id.to_string(),
                identifier: rec.identifier,
                password_hash: rec.password_hash,
            },
        })
    }
    async fn update_user(&self, user: User) -> Result<(), crate::error::AuthError> {
        // Convert String user_id to Uuid
        let cred_user_id = Uuid::parse_str(&user.credentials.user_id)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        // Update credentials (identifier and password_hash)
        sqlx::query!(
            "UPDATE cryptic_credentials SET identifier = $1, password_hash = $2 WHERE user_id = $3",
            user.credentials.identifier,
            user.credentials.password_hash,
            cred_user_id
        )
        .execute(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }
    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError> {
        let uuid = Uuid::parse_str(id).map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let mut conn = self
            .pool
            .acquire()
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        sqlx::query!("DELETE FROM cryptic_users WHERE id = $1", uuid)
            .execute(&mut *conn)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}
