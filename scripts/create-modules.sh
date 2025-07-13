#!/bin/bash
# scripts/create-modules.sh - Créer les modules spécialisés

set -e

echo "🏗️ Création des modules spécialisés..."

SRC_DIR="src"

# src/user/mod.rs
echo "  - Création du module user..."
cat > "$SRC_DIR/user/mod.rs" << 'EOF'
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
EOF

touch "$SRC_DIR/user/repository.rs"

# src/password/mod.rs
echo "  - Création du module password..."
cat > "$SRC_DIR/password/mod.rs" << 'EOF'
// src/password/mod.rs - L'Encre Indélébile des Mots de Passe

//! Ce module gère le hachage et la vérification sécurisée des mots de passe.

use crate::error::AuthError;

/// Trait pour abstraire le hachage et la vérification des mots de passe.
#[async_trait::async_trait]
pub trait PasswordHasher {
    /// Hashe un mot de passe donné.
    async fn hash_password(&self, password: &str) -> Result<String, AuthError>;
    /// Vérifie si un mot de passe clair correspond à un hachage donné.
    async fn verify_password(&self, password: &str, hashed_password: &str) -> Result<bool, AuthError>;
}
EOF

# src/token/mod.rs
echo "  - Création du module token..."
cat > "$SRC_DIR/token/mod.rs" << 'EOF'
// src/token/mod.rs - Les Fragments de Destin des Tokens

//! Ce module gère la création, la validation et le rafraîchissement des tokens d'authentification.

use crate::error::AuthError;

/// Représente une paire de tokens (accès et rafraîchissement).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
}

/// Trait pour abstraire les opérations de token.
#[async_trait::async_trait]
pub trait TokenService {
    /// Génère une nouvelle paire de tokens pour un utilisateur donné.
    async fn generate_token_pair(&self, user_id: &str, user_roles: &[String]) -> Result<TokenPair, AuthError>;
    /// Valide un token d'accès et extrait ses revendications.
    async fn validate_access_token<C: serde::de::DeserializeOwned + crate::token::claims::Claims + Send>(&self, token: &str) -> Result<C, AuthError>;
    /// Rafraîchit un token d'accès en utilisant un token de rafraîchissement.
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError>;
}

/// Les revendications (claims) par défaut pour les JWT.
pub mod claims;
EOF

# src/token/claims.rs
echo "  - Création du module token claims..."
cat > "$SRC_DIR/token/claims.rs" << 'EOF'
// src/token/claims.rs - Les Revendications Secrètes des Tokens

//! Définit les structures de revendications (claims) pour les tokens d'authentification.

use serde::{Serialize, Deserialize};
use chrono::{Utc, serde::ts_seconds};

/// Trait commun pour toutes les revendications de token.
pub trait Claims {
    fn expiration(&self) -> i64;
    fn set_expiration(&mut self, exp: i64);
    fn issued_at(&self) -> i64;
    fn set_issued_at(&mut self, iat: i64);
}

/// Revendications par défaut pour un token d'accès JWT.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String, // Subject (user ID)
    pub roles: Vec<String>, // User roles
    #[serde(with = "ts_seconds")]
    pub exp: chrono::DateTime<Utc>, // Expiration timestamp
    #[serde(with = "ts_seconds")]
    pub iat: chrono::DateTime<Utc>, // Issued at timestamp
    pub aud: Option<String>, // Audience
    pub iss: Option<String>, // Issuer
}

impl Claims for AccessClaims {
    fn expiration(&self) -> i64 {
        self.exp.timestamp()
    }
    fn set_expiration(&mut self, exp: i64) {
        self.exp = Utc.timestamp_opt(exp, 0).unwrap();
    }
    fn issued_at(&self) -> i64 {
        self.iat.timestamp()
    }
    fn set_issued_at(&mut self, iat: i64) {
        self.iat = Utc.timestamp_opt(iat, 0).unwrap();
    }
}
EOF

# src/policy/mod.rs
echo "  - Création du module policy..."
cat > "$SRC_DIR/policy/mod.rs" << 'EOF'
// src/policy/mod.rs - Les Lignes Directrices de Sécurité

//! Ce module définit les politiques et règles de sécurité,
//! comme les exigences de complexité des mots de passe.

use crate::error::AuthError;

/// Définit les exigences pour un mot de passe fort.
pub struct PasswordPolicy {
    pub min_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special_char: bool,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        PasswordPolicy {
            min_length: 12,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special_char: true,
        }
    }
}

impl PasswordPolicy {
    /// Valide si un mot de passe respecte la politique définie.
    pub fn validate_password(&self, password: &str) -> Result<(), AuthError> {
        if password.len() < self.min_length {
            return Err(AuthError::InvalidInput(format!(
                "Password must be at least {} characters long.",
                self.min_length
            )));
        }

        if self.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
            return Err(AuthError::InvalidInput("Password must contain at least one uppercase letter.".to_string()));
        }
        if self.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
            return Err(AuthError::InvalidInput("Password must contain at least one lowercase letter.".to_string()));
        }
        if self.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
            return Err(AuthError::InvalidInput("Password must contain at least one digit.".to_string()));
        }
        if self.require_special_char && !password.chars().any(|c| !c.is_ascii_alphanumeric()) {
            return Err(AuthError::InvalidInput("Password must contain at least one special character.".to_string()));
        }
        Ok(())
    }
}
EOF

# src/rbac/mod.rs
echo "  - Création du module rbac..."
cat > "$SRC_DIR/rbac/mod.rs" << 'EOF'
// src/rbac/mod.rs - Les Gardiens des Royaumes (Contrôle d'Accès Basé sur les Rôles)

//! Ce module fournit des fonctionnalités pour le contrôle d'accès basé sur les rôles (RBAC).

use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Role {
    Admin,
    User,
    Moderator,
    Guest,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Permission {
    ViewUser,
    ManageUsers,
    CreateContent,
    EditContent,
    DeleteContent,
}

pub struct RbacManager {
    role_permissions: HashMap<Role, Vec<Permission>>,
}

impl RbacManager {
    pub fn new() -> Self {
        let mut rp = HashMap::new();
        // Définir les permissions pour chaque rôle
        rp.insert(Role::Admin, vec![
            Permission::ViewUser, Permission::ManageUsers,
            Permission::CreateContent, Permission::EditContent, Permission::DeleteContent
        ]);
        rp.insert(Role::User, vec![
            Permission::ViewUser, Permission::CreateContent
        ]);
        rp.insert(Role::Moderator, vec![
            Permission::ViewUser, Permission::EditContent, Permission::DeleteContent
        ]);
        rp.insert(Role::Guest, vec![
            Permission::ViewUser
        ]);
        Self { role_permissions: rp }
    }

    /// Vérifie si un rôle donné a une certaine permission.
    pub fn has_permission(&self, role: &Role, permission: &Permission) -> bool {
        self.role_permissions
            .get(role)
            .map_or(false, |perms| perms.contains(permission))
    }

    /// Vérifie si un utilisateur (avec ses rôles) a une certaine permission.
    pub fn user_has_permission(&self, user_roles: &[Role], permission: &Permission) -> bool {
        user_roles.iter().any(|role| self.has_permission(role, permission))
    }
}
EOF

echo "  ✓ Modules spécialisés créés avec succès !"
