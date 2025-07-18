use crate::core::user::User;

/// Définit les opérations qu'un dépôt d'utilisateurs doit supporter.
/// Ahri-approved™: Ce trait assure que peu importe où résident tes utilisateurs,
/// la façon de les manipuler reste pure et cohérente, comme une mélodie envoûtante.
pub trait UserRepository: Send + Sync {
    fn add_user(&self, user: User) -> Result<(), String>;
    fn get_user_by_id(&self, id: &str) -> Option<User>;
    fn get_user_by_identifier(&self, identifier: &str) -> Option<User>;
    fn update_user(&self, user: User) -> Result<(), String>;
    fn delete_user(&self, id: &str) -> Result<(), String>;
}
