use crate::core::user::User;
use std::sync::{Arc, Mutex}; // Pour une gestion concurrente sécurisée // S'assurer que le chemin est correct pour ton struct User

/// Définit les opérations qu'un dépôt d'utilisateurs doit supporter.
/// Ahri-approved™: Ce trait assure que peu importe où résident tes utilisateurs,
/// la façon de les manipuler reste pure et cohérente, comme une mélodie envoûtante.
pub trait UserRepository: Send + Sync {
    fn add_user(&self, user: User) -> Result<(), String>;
    fn get_user_by_id(&self, id: &str) -> Option<User>;
    // ... tu pourrais ajouter d'autres méthodes ici comme update_user, delete_user
}

#[derive(Default, Debug)]
pub struct InMemoryUserRepo {
    // Utiliser Arc<Mutex<Vec<User>>> pour permettre le partage et la modification thread-safe.
    // C'est comme le sanctuaire intérieur d'Ahri, toujours protégé et accessible.
    users: Arc<Mutex<Vec<User>>>,
}

impl InMemoryUserRepo {
    pub fn new() -> Self {
        InMemoryUserRepo {
            users: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

// Implémentation du trait pour notre dépôt en mémoire
impl UserRepository for InMemoryUserRepo {
    fn add_user(&self, user: User) -> Result<(), String> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| format!("Failed to lock users: {}", e))?;
        users.push(user);
        Ok(())
    }

    fn get_user_by_id(&self, id: &str) -> Option<User> {
        let users = self.users.lock().ok()?; // Handle potential poisoning
        users.iter().find(|u| u.id == id).cloned()
    }
}

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
}

