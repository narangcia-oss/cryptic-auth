use async_trait::async_trait;

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

#[async_trait]
impl UserRepository for InMemoryUserRepo {
    async fn add_user(&self, user: User) -> Result<User, crate::error::AuthError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| crate::error::AuthError::ServiceUnavailable(e.to_string()))?;
        users.push(user.clone());
        Ok(user.clone())
    }

    async fn get_user_by_id(&self, id: &str) -> Option<User> {
        let users = self.users.lock().ok()?; // Handle potential poisoning
        users.iter().find(|u| u.id == id).cloned()
    }

    async fn get_user_by_identifier(&self, identifier: &str) -> Option<User> {
        let users = self.users.lock().ok()?; // Handle potential poisoning
        users
            .iter()
            .find(|u| u.credentials.identifier == identifier)
            .cloned()
    }

    async fn update_user(&self, user: User) -> Result<(), crate::error::AuthError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| crate::error::AuthError::ServiceUnavailable(e.to_string()))?;
        if let Some(existing) = users.iter_mut().find(|u| u.id == user.id) {
            *existing = user;
            Ok(())
        } else {
            Err(crate::error::AuthError::UserNotFound)
        }
    }

    async fn delete_user(&self, id: &str) -> Result<(), crate::error::AuthError> {
        let mut users = self
            .users
            .lock()
            .map_err(|e| crate::error::AuthError::ServiceUnavailable(e.to_string()))?;
        let len_before = users.len();
        users.retain(|u| u.id != id);
        if users.len() < len_before {
            Ok(())
        } else {
            Err(crate::error::AuthError::UserNotFound)
        }
    }
}
