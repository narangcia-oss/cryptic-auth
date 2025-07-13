// src/user/mod.rs - Gestion des Profils d'Utilisateurs

//! Ce module définit les structures de données pour les utilisateurs
//! et les traits pour les opérations de persistance.

/// Représente un utilisateur enregistré dans le système.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
}

/// Représente les identifiants fournis lors de la connexion ou de l'inscription.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub identifier: String, // Nom d'utilisateur ou email
    pub password: String,
}

/// Trait pour abstraire les opérations de persistance des utilisateurs.
#[async_trait::async_trait]
pub trait UserRepository {
    /// Trouve un utilisateur par son identifiant (username ou email).
    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<User>, crate::error::AuthError>;
    /// Crée un nouvel utilisateur dans la persistance.
    async fn create(&self, user: User) -> Result<User, crate::error::AuthError>;
    /// Met à jour un utilisateur existant.
    async fn update(&self, user: User) -> Result<User, crate::error::AuthError>;
}
