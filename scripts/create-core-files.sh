#!/bin/bash
# scripts/create-core-files.sh - Créer les fichiers principaux du crate

set -e

echo "📝 Création des fichiers principaux..."

SRC_DIR="src"
CRATE_NAME="z3-auth"

# src/lib.rs
echo "  - Création de '$SRC_DIR/lib.rs'..."
cat > "$SRC_DIR/lib.rs" << 'EOF'
// src/lib.rs - La Porte Principale de l'Authentification

//! Une crate d'authentification robuste et sécurisée, inspirée par la sagesse d'Ahri.
//! Elle fournit des outils pour la gestion des utilisateurs, le hachage des mots de passe,
//! la gestion des sessions et des tokens, et bien plus encore.

// Rendre les modules publics pour qu'ils soient accessibles aux utilisateurs de la crate
pub mod auth_service;
pub mod error;
pub mod password;
pub mod policy;
pub mod token;
pub mod user;
pub mod rbac; // Module optionnel pour le contrôle d'accès basé sur les rôles
pub mod utils;

// Réexporter les éléments clés pour une utilisation plus facile
pub use auth_service::AuthService;
pub use error::AuthError;

// Vous pouvez ajouter d'autres 'use' ici au fur et à mesure que votre crate grandit
// Par exemple:
// pub use user::{User, Credentials};
// pub use token::TokenPair;
EOF

# src/error.rs
echo "  - Création de '$SRC_DIR/error.rs'..."
cat > "$SRC_DIR/error.rs" << 'EOF'
// src/error.rs - Le Miroir des Échecs Sécurisés

use thiserror::Error;

/// Représente toutes les erreurs qui peuvent survenir au sein de la crate d'authentification.
/// Inspiré par les défis que même la magie d'Ahri doit surmonter.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials provided.")]
    InvalidCredentials,
    #[error("User already exists.")]
    UserAlreadyExists,
    #[error("Password hashing failed: {0}")]
    HashingError(String),
    #[error("Password verification failed: {0}")]
    PasswordVerificationError(String),
    #[error("Token creation failed: {0}")]
    TokenCreationError(String),
    #[error("Token validation failed: {0}")]
    TokenValidationError(String),
    #[error("Token refresh failed: {0}")]
    TokenRefreshError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Service indisponible: {0}")]
    ServiceUnavailable(String),
    #[error("Feature not implemented yet: {0}")]
    NotImplemented(String),
    #[error("Invalid input data: {0}")]
    InvalidInput(String),
}
EOF

# src/auth_service.rs
echo "  - Création de '$SRC_DIR/auth_service.rs'..."
cat > "$SRC_DIR/auth_service.rs" << 'EOF'
// src/auth_service.rs - Le Grand Orchestrateur des Opérations d'Authentification

//! Ce module contient la logique de haut niveau pour l'authentification des utilisateurs,
//! agissant comme le point central des interactions de la crate.

use crate::error::AuthError;

/// La structure principale du service d'authentification.
/// Elle agrège les dépendances nécessaires pour effectuer les opérations.
pub struct AuthService {
    // Exemple de champs qui pourraient être nécessaires
    // user_repo: Box<dyn UserRepository + Send + Sync>,
    // password_hasher: Box<dyn PasswordHasher + Send + Sync>,
    // token_service: Box<dyn TokenService + Send + Sync>,
}

impl AuthService {
    /// Crée une nouvelle instance de AuthService.
    pub fn new() -> Self {
        AuthService {}
    }

    /// Tente d'enregistrer un nouvel utilisateur.
    pub async fn signup(&self) -> Result<(), AuthError> {
        println!("Tentative d'inscription...");
        Err(AuthError::NotImplemented("signup".to_string()))
    }

    /// Tente de connecter un utilisateur.
    pub async fn login(&self) -> Result<(), AuthError> {
        println!("Tentative de connexion...");
        Err(AuthError::NotImplemented("login".to_string()))
    }
}
EOF

# src/utils.rs
echo "  - Création de '$SRC_DIR/utils.rs'..."
cat > "$SRC_DIR/utils.rs" << 'EOF'
// src/utils.rs - Le Coffre à Outils Magique

//! Ce module contient des fonctions utilitaires générales utilisées à travers la crate.

/// Génère une chaîne aléatoire sécurisée pour les clés ou sels.
pub fn generate_random_string(length: usize) -> String {
    use rand::{thread_rng, Rng};
    let chars: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..length)
        .map(|_| {
            let idx = thread_rng().gen_range(0..chars.len());
            chars[idx] as char
        })
        .collect()
}
EOF

echo "  ✓ Fichiers principaux créés avec succès !"
