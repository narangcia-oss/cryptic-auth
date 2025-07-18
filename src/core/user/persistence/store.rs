use super::{in_memory::InMemoryUserRepo, traits::UserRepository};
use crate::core::user::User;
use async_trait::async_trait;

#[cfg(feature = "sqlx")]
use crate::core::user::persistence::PgUserRepo;

#[derive(Debug)]
pub enum PersistentUsers {
    InMemory(InMemoryUserRepo),
    #[cfg(feature = "sqlx")]
    Database(PgUserRepo),
    // FileSystem(FsUserRepo),
}

impl PersistentUsers {
    pub fn in_memory() -> Self {
        PersistentUsers::InMemory(InMemoryUserRepo::new())
    }
    #[cfg(feature = "sqlx")]
    pub fn database(repo: PgUserRepo) -> Self {
        PersistentUsers::Database(repo)
    }
}

#[async_trait]
impl UserRepository for PersistentUsers {
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError> {
        match self {
            PersistentUsers::InMemory(repo) => repo.add_user(user).await,
            #[cfg(feature = "sqlx")]
            PersistentUsers::Database(repo) => repo.add_user(user).await,
        }
    }

    async fn get_user_by_id(&self, id: &str) -> Option<User> {
        match self {
            PersistentUsers::InMemory(repo) => repo.get_user_by_id(id).await,
            #[cfg(feature = "sqlx")]
            PersistentUsers::Database(repo) => repo.get_user_by_id(id).await,
        }
    }

    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        match self {
            PersistentUsers::InMemory(repo) => repo.get_user_by_identifier(identifier).await,
            #[cfg(feature = "sqlx")]
            PersistentUsers::Database(repo) => repo.get_user_by_identifier(identifier).await,
        }
    }

    async fn update_user(&self, user: User) -> Result<(), crate::error::AuthError> {
        match self {
            PersistentUsers::InMemory(repo) => repo.update_user(user).await,
            #[cfg(feature = "sqlx")]
            PersistentUsers::Database(repo) => repo.update_user(user).await,
        }
    }

    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError> {
        match self {
            PersistentUsers::InMemory(repo) => repo.delete_user(id).await,
            #[cfg(feature = "sqlx")]
            PersistentUsers::Database(repo) => repo.delete_user(id).await,
        }
    }
}
