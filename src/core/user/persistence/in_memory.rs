use super::traits::UserRepository;
use crate::core::user::User;
use std::sync::{Arc, Mutex};

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
            .map_err(|e| format!("Failed to lock users: {e}"))?;
        users.push(user);
        Ok(())
    }

    fn get_user_by_id(&self, id: &str) -> Option<User> {
        let users = self.users.lock().ok()?; // Handle potential poisoning
        users.iter().find(|u| u.id == id).cloned()
    }

    fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        let users = self.users.lock().ok()?; // Handle potential poisoning
        users
            .iter()
            .find(|u| u.credentials.identifier == identifier)
            .cloned()
    }

    fn update_user(&self, user: User) -> Result<(), String> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| format!("Failed to lock users: {e}"))?;
        if let Some(existing) = users.iter_mut().find(|u| u.id == user.id) {
            *existing = user;
            Ok(())
        } else {
            Err("User not found".to_string())
        }
    }

    fn delete_user(&self, id: &str) -> Result<(), String> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| format!("Failed to lock users: {e}"))?;
        let len_before = users.len();
        users.retain(|u| u.id != id);
        if users.len() < len_before {
            Ok(())
        } else {
            Err("User not found".to_string())
        }
    }
}
