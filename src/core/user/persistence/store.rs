use super::{in_memory::InMemoryUserRepo, traits::UserRepository};
use crate::core::user::User;

/// Enumération des différents types de dépôts d'utilisateurs persistants.
/// Ahri-approved™: Choisis ta voie, et Ahri veillera à ce qu'elle soit éclairée.
#[derive(Debug)] // Pas besoin de Default ici si tu construis explicitement
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

// Pour interagir avec ton dépôt peu importe son type
impl UserRepository for PersistentUsers {
    fn add_user(&self, user: User) -> Result<(), String> {
        match self {
            PersistentUsers::InMemory(repo) => repo.add_user(user),
            #[cfg(feature = "sqlx")]
            PersistentUsers::Database(repo) => repo.add_user(user),
        }
    }

    fn get_user_by_id(&self, id: &str) -> Option<User> {
        match self {
            PersistentUsers::InMemory(repo) => repo.get_user_by_id(id),
            #[cfg(feature = "sqlx")]
            PersistentUsers::Database(repo) => repo.get_user_by_id(id),
        }
    }

    fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        match self {
            PersistentUsers::InMemory(repo) => repo.get_user_by_identifier(identifier),
            #[cfg(feature = "sqlx")]
            PersistentUsers::Database(repo) => repo.get_user_by_identifier(identifier),
        }
    }

    fn update_user(&self, user: User) -> Result<(), String> {
        match self {
            PersistentUsers::InMemory(repo) => repo.update_user(user),
            #[cfg(feature = "sqlx")]
            PersistentUsers::Database(repo) => repo.update_user(user),
        }
    }

    fn delete_user(&self, id: &str) -> Result<(), String> {
        match self {
            PersistentUsers::InMemory(repo) => repo.delete_user(id),
            #[cfg(feature = "sqlx")]
            PersistentUsers::Database(repo) => repo.delete_user(id),
        }
    }
}

#[cfg(feature = "sqlx")]
pub use pg_user_repo::PgUserRepo;
#[cfg(feature = "sqlx")]
mod pg_user_repo;
