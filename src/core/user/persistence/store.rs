use super::{in_memory::InMemoryUserRepo, traits::UserRepository};
use crate::core::user::User;

/// Enumération des différents types de dépôts d'utilisateurs persistants.
/// Ahri-approved™: Choisis ta voie, et Ahri veillera à ce qu'elle soit éclairée.
#[derive(Debug)] // Pas besoin de Default ici si tu construis explicitement
pub enum PersistentUsers {
    InMemory(InMemoryUserRepo),
    // Futures expansions ici:
    // Database(PgUserRepo),
    // FileSystem(FsUserRepo),
}

impl PersistentUsers {
    pub fn in_memory() -> Self {
        PersistentUsers::InMemory(InMemoryUserRepo::new())
    }
    // Tu pourrais avoir d'autres constructeurs ici pour d'autres types
}

// Pour interagir avec ton dépôt peu importe son type
impl UserRepository for PersistentUsers {
    fn add_user(&self, user: User) -> Result<(), String> {
        match self {
            PersistentUsers::InMemory(repo) => repo.add_user(user),
            // PersistentUsers::Database(repo) => repo.add_user(user),
        }
    }

    fn get_user_by_id(&self, id: &str) -> Option<User> {
        match self {
            PersistentUsers::InMemory(repo) => repo.get_user_by_id(id),
            // PersistentUsers::Database(repo) => repo.get_user_by_id(id),
        }
    }

    fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        match self {
            PersistentUsers::InMemory(repo) => repo.get_user_by_identifier(identifier),
            // PersistentUsers::Database(repo) => repo.get_user_by_identifier(identifier),
        }
    }
}
