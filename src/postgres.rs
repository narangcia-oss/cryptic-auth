//! Postgres-backed user repository implementation for the Cryptic authentication system.
//!
//! This module provides the [`PgUserRepo`] struct, which implements the user repository
//! trait for storing and retrieving user and credential data in a PostgreSQL database.
//!
//! # Features
//!
//! - Comprehensive schema validation for required tables and constraints
//! - Async operations using `tokio` and `sqlx`
//! - Implements the [`UserRepository`] trait for user CRUD operations
//!
//! # Usage
//!
//! This module is only available when the `postgres` feature is enabled.

use async_trait::async_trait;
use uuid::Uuid;

#[cfg(feature = "postgres")]
use crate::{core::user::User, error::AuthError};

#[cfg(feature = "postgres")]
use tokio::sync::Mutex;

/// A PostgreSQL-backed implementation of the user repository.
///
/// This struct manages a single mutable PostgreSQL connection for user and credential operations.
/// If you need connection pooling, wrap this repository in a pool-aware struct.
#[derive(Debug)]
#[cfg(feature = "postgres")]
pub struct PgUserRepo {
    /// The underlying PostgreSQL connection, protected by a mutex for safe concurrent access.
    conn: Mutex<sqlx::PgConnection>,
}

#[cfg(feature = "postgres")]
impl PgUserRepo {
    /// Checks that the required PostgreSQL schema for Cryptic exists and is valid.
    ///
    /// This function verifies the existence and structure of the `cryptic_users` and
    /// `cryptic_credentials` tables, their columns, primary keys, unique constraints,
    /// and foreign key relationships.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::DatabaseError`] if any required table, column, or constraint is missing or invalid.
    pub async fn check_schema(
        conn: &mut sqlx::PgConnection,
    ) -> Result<(), crate::error::AuthError> {
        use sqlx::Row;
        // Check if the cryptic_users table exists
        // Check cryptic_users table
        let user_cols = sqlx::query(
            r#"SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_name = 'cryptic_users'"#,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("cryptic_users table missing: {e}")))?;
        let mut has_id = false;
        for col in &user_cols {
            let name: &str = col.get("column_name");
            let dtype: &str = col.get("data_type");
            if name == "id" && dtype == "uuid" {
                has_id = true;
            }
        }
        if !has_id {
            return Err(AuthError::DatabaseError(
                "cryptic_users.id column missing or wrong type".to_string(),
            ));
        }

        // Check primary key on cryptic_users.id
        let pk = sqlx::query(
            r#"SELECT kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                WHERE tc.table_name = 'cryptic_users' AND tc.constraint_type = 'PRIMARY KEY'"#,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("cryptic_users PK check failed: {e}")))?;
        let mut pk_ok = false;
        for row in &pk {
            let col: &str = row.get("column_name");
            if col == "id" {
                pk_ok = true;
            }
        }
        if !pk_ok {
            return Err(AuthError::DatabaseError(
                "cryptic_users.id is not primary key".to_string(),
            ));
        }

        // Check cryptic_credentials table
        let cred_cols = sqlx::query(
            r#"SELECT column_name, data_type, is_nullable
                FROM information_schema.columns
                WHERE table_name = 'cryptic_credentials'"#,
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("cryptic_credentials table missing: {e}")))?;
        let mut has_user_id = false;
        let mut has_identifier = false;
        let mut has_password_hash = false;
        for col in &cred_cols {
            let name: &str = col.get("column_name");
            let dtype: &str = col.get("data_type");
            if name == "user_id" && dtype == "uuid" {
                has_user_id = true;
            }
            if name == "identifier" && dtype == "character varying" {
                has_identifier = true;
            }
            if name == "password_hash" && dtype == "character varying" {
                has_password_hash = true;
            }
        }
        if !has_user_id || !has_identifier || !has_password_hash {
            return Err(AuthError::DatabaseError(
                "cryptic_credentials columns missing or wrong types".to_string(),
            ));
        }

        // Check PK on cryptic_credentials.user_id
        let cred_pk = sqlx::query(
            r#"SELECT kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                WHERE tc.table_name = 'cryptic_credentials' AND tc.constraint_type = 'PRIMARY KEY'"#
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("cryptic_credentials PK check failed: {e}")))?;
        let mut cred_pk_ok = false;
        for row in &cred_pk {
            let col: &str = row.get("column_name");
            if col == "user_id" {
                cred_pk_ok = true;
            }
        }
        if !cred_pk_ok {
            return Err(AuthError::DatabaseError(
                "cryptic_credentials.user_id is not primary key".to_string(),
            ));
        }

        // Check unique constraint on identifier
        let _unique_identifier = sqlx::query(
            r#"SELECT tc.constraint_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.constraint_column_usage ccu
                  ON tc.constraint_name = ccu.constraint_name
                WHERE tc.table_name = 'cryptic_credentials' AND tc.constraint_type = 'UNIQUE' AND ccu.column_name = 'identifier'"#
        )
        .fetch_one(&mut *conn)
        .await
        .map_err(|_| AuthError::DatabaseError("cryptic_credentials.identifier is not unique".to_string()))?;

        // Check FK from cryptic_credentials.user_id to cryptic_users.id
        let fk = sqlx::query(
            r#"SELECT kcu.column_name, ccu.table_name AS foreign_table_name, ccu.column_name AS foreign_column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                JOIN information_schema.constraint_column_usage ccu
                  ON tc.constraint_name = ccu.constraint_name
                WHERE tc.table_name = 'cryptic_credentials' AND tc.constraint_type = 'FOREIGN KEY'"#
        )
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| AuthError::DatabaseError(format!("cryptic_credentials FK check failed: {e}")))?;
        let mut fk_ok = false;
        for row in &fk {
            let col: &str = row.get("column_name");
            let ftable: &str = row.get("foreign_table_name");
            let fcol: &str = row.get("foreign_column_name");
            if col == "user_id" && ftable == "cryptic_users" && fcol == "id" {
                fk_ok = true;
            }
        }
        if !fk_ok {
            return Err(AuthError::DatabaseError(
                "cryptic_credentials.user_id does not reference cryptic_users.id".to_string(),
            ));
        }

        Ok(())
    }

    /// Creates a new [`PgUserRepo`] instance from a PostgreSQL connection.
    ///
    /// # Arguments
    ///
    /// * `conn` - An established [`sqlx::PgConnection`] to the database.
    ///
    /// # Returns
    ///
    /// Returns a new [`PgUserRepo`] instance wrapped in a mutex.
    ///
    /// # Errors
    ///
    /// This function does not perform schema validation. Call [`check_schema`] separately if needed.
    pub async fn new(conn: sqlx::PgConnection) -> Result<Self, crate::error::AuthError> {
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

#[cfg(feature = "postgres")]
#[async_trait]
impl crate::core::user::persistence::traits::UserRepository for PgUserRepo {
    /// Adds a new user and their credentials to the database.
    ///
    /// # Arguments
    ///
    /// * `user` - The [`User`] struct to insert.
    ///
    /// # Returns
    ///
    /// Returns the inserted [`User`] on success.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::DatabaseError`] if insertion fails or IDs are invalid.
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError> {
        // Convert String IDs to Uuid
        let user_id =
            Uuid::parse_str(&user.id).map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let cred_user_id = Uuid::parse_str(&user.credentials.user_id)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;

        // Insert into cryptic_users
        let mut conn = self.conn.lock().await;
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

    /// Retrieves a user and their credentials by user ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The user ID as a string (UUID format).
    ///
    /// # Returns
    ///
    /// Returns [`Some(User)`] if found, or [`None`] if not found or ID is invalid.
    async fn get_user_by_id(&self, id: &str) -> Option<User> {
        let uuid = Uuid::parse_str(id).ok()?;
        let mut conn = self.conn.lock().await;
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

    /// Retrieves a user and their credentials by identifier (e.g., username or email).
    ///
    /// # Arguments
    ///
    /// * `identifier` - The unique identifier for the user.
    ///
    /// # Returns
    ///
    /// Returns [`Some(User)`] if found, or [`None`] if not found.
    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        let mut conn = self.conn.lock().await;
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

    /// Updates a user's credentials (identifier and password hash).
    ///
    /// # Arguments
    ///
    /// * `user` - The [`User`] struct with updated credentials.
    ///
    /// # Returns
    ///
    /// Returns [`Ok(())`] on success, or [`AuthError::DatabaseError`] on failure.
    async fn update_user(&self, user: User) -> Result<(), crate::error::AuthError> {
        // Convert String user_id to Uuid
        let cred_user_id = Uuid::parse_str(&user.credentials.user_id)
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let mut conn = self.conn.lock().await;
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

    /// Deletes a user and their credentials from the database by user ID.
    ///
    /// # Arguments
    ///
    /// * `id` - The user ID as a string (UUID format).
    ///
    /// # Returns
    ///
    /// Returns [`Ok(())`] on success, or [`AuthError::DatabaseError`] on failure.
    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError> {
        let uuid = Uuid::parse_str(id).map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        let mut conn = self.conn.lock().await;
        sqlx::query!("DELETE FROM cryptic_users WHERE id = $1", uuid)
            .execute(&mut *conn)
            .await
            .map_err(|e| AuthError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}
