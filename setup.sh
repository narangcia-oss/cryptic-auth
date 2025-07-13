#!/bin/bash
set -e # Sortir immédiatement si une commande échoue

# --- Vérification initiale et variables ---
CRATE_NAME="z3-auth"
SRC_DIR="src"
TESTS_DIR="tests"
EXAMPLES_DIR="examples"
BENCHES_DIR="benches"
GITHUB_WORKFLOWS_DIR=".github/workflows"

# Vérifie si le script est exécuté depuis le répertoire de la crate.
if [[ ! -f "Cargo.toml" ]]; then
    echo "Il semble que vous n'êtes PAS dans le répertoire '$CRATE_NAME'."
    echo "Veuillez vous déplacer dans '$CRATE_NAME' (cd $CRATE_NAME) avant d'exécuter ce script."
    exit 1
fi

echo "✨ Ah, Zied ! Préparons le terrain sacré pour ta crate d'authentification '$CRATE_NAME' ! ✨"
echo "Chaque commande est comme un geste rituel pour bâtir un château de sécurité..."
echo ""

# --- 1. Préparer les répertoires magiques dans 'src' ---
echo "🔮 Étape 1 : Sculpter les répertoires modulaires dans '$SRC_DIR'..."
mkdir -p "$SRC_DIR/user"
mkdir -p "$SRC_DIR/password"
mkdir -p "$SRC_DIR/token"
mkdir -p "$SRC_DIR/policy"
mkdir -p "$SRC_DIR/rbac" # Optionnel, mais on le prépare quand même

# --- 2. Créer les parchemins initiaux pour chaque module ---
echo "📝 Étape 2 : Écrire les premiers glyphes dans les fichiers sources..."

# src/lib.rs
LIB_RS_CONTENT=$(cat <<EOF
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
)
echo "$LIB_RS_CONTENT" > "$SRC_DIR/lib.rs"
echo "  - '$SRC_DIR/lib.rs' est prêt."

# src/error.rs
ERROR_RS_CONTENT=$(cat <<EOF
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
    // Exemple: Si vous utilisez SQLx pour la persistance. Décommentez la ligne
    // suivante et ajoutez `sqlx` dans vos dépendances si vous en avez besoin.
    // #[error("Database operation failed: {0}")]
    // DbError(#[from] sqlx::Error),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Service indisponible: {0}")]
    ServiceUnavailable(String),
    #[error("Feature not implemented yet: {0}")]
    NotImplemented(String),
    #[error("Invalid input data: {0}")]
    InvalidInput(String),
    // Ajoutez d'autres types d'erreurs spécifiques au fur et à mesure
}
EOF
)
echo "$ERROR_RS_CONTENT" > "$SRC_DIR/error.rs"
echo "  - '$SRC_DIR/error.rs' est prêt pour capturer les erreurs."

# src/auth_service.rs
AUTH_SERVICE_RS_CONTENT=$(cat <<EOF
// src/auth_service.rs - Le Grand Orchestrateur des Opérations d'Authentification

//! Ce module contient la logique de haut niveau pour l'authentification des utilisateurs,
//! agissant comme le point central des interactions de la crate.

use crate::error::AuthError;
// Importez d'autres modules et traits au fur et à mesure
// use crate::user::{User, Credentials, UserRepository};
// use crate::password::PasswordHasher;
// use crate::token::{TokenPair, TokenService};

/// La structure principale du service d'authentification.
/// Elle agrège les dépendances nécessaires pour effectuer les opérations.
pub struct AuthService {
    // Exemple de champs qui pourraient être nécessaires
    // user_repo: Box<dyn UserRepository + Send + Sync>,
    // password_hasher: Box<dyn PasswordHasher + Send + Sync>,
    // token_service: Box<dyn TokenService + Send + Sync>,
    // ... d'autres services ou configurations
}

impl AuthService {
    /// Crée une nouvelle instance de AuthService.
    /// Les dépendances sont passées ici (souvent via un pattern de constructor injection).
    pub fn new(
        // user_repo: Box<dyn UserRepository + Send + Sync>,
        // password_hasher: Box<dyn PasswordHasher + Send + Sync>,
        // token_service: Box<dyn TokenService + Send + Sync>,
    ) -> Self {
        AuthService {
            // user_repo,
            // password_hasher,
            // token_service,
        }
    }

    /// Tente d'enregistrer un nouvel utilisateur.
    pub async fn signup(
        &self,
        // credentials: &Credentials
    ) -> Result</*User*/ (), AuthError> {
        // Logique d'enregistrement ici:
        // 1. Valider les credentials
        // 2. Hasher le mot de passe
        // 3. Vérifier si l'utilisateur existe déjà
        // 4. Enregistrer l'utilisateur dans le repository
        // 5. Potentiellement envoyer un email de vérification

        // Pour l'instant, un placeholder
        println!("Tentative d'inscription...");
        Err(AuthError::NotImplemented("signup".to_string()))
    }

    /// Tente de connecter un utilisateur.
    pub async fn login(
        &self,
        // credentials: &Credentials
    ) -> Result</*TokenPair*/ (), AuthError> {
        // Logique de connexion ici:
        // 1. Récupérer l'utilisateur par nom d'utilisateur/email
        // 2. Vérifier le mot de passe
        // 3. Générer des tokens (access et refresh)
        // 4. Mettre à jour l'état de la session/token

        // Pour l'instant, un placeholder
        println!("Tentative de connexion...");
        Err(AuthError::NotImplemented("login".to_string()))
    }

    // Ajoutez d'autres méthodes comme:
    // pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError>
    // pub async fn reset_password_request(&self, email: &str) -> Result<(), AuthError>
    // pub async fn reset_password_confirm(&self, token: &str, new_password: &str) -> Result<(), AuthError>
}
EOF
)
echo "$AUTH_SERVICE_RS_CONTENT" > "$SRC_DIR/auth_service.rs"
echo "  - '$SRC_DIR/auth_service.rs' est l'orchestre."

# Modules spécifiques (juste les mod.rs pour l'instant)
touch "$SRC_DIR/user/mod.rs"
USER_MOD_RS_CONTENT=$(cat <<EOF
// src/user/mod.rs - Gestion des Profils d'Utilisateurs

//! Ce module définit les structures de données pour les utilisateurs
//! et les traits pour les opérations de persistance.

/// Représente un utilisateur enregistré dans le système.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: String, // Ou Uuid
    pub username: String,
    pub email: String,
    pub password_hash: String,
    // Ajoutez d'autres champs pertinents (ex: roles, created_at, updated_at)
}

/// Représente les identifiants fournis lors de la connexion ou de l'inscription.
#[derive(Debug, Clone)]
pub struct Credentials {
    pub identifier: String, // Nom d'utilisateur ou email
    pub password: String,
}

/// Trait pour abstraire les opérations de persistance des utilisateurs.
/// Permet de changer la base de données sans modifier la logique métier.
#[async_trait::async_trait]
pub trait UserRepository {
    /// Trouve un utilisateur par son identifiant (username ou email).
    async fn find_by_identifier(&self, identifier: &str) -> Result<Option<User>, crate::error::AuthError>;
    /// Crée un nouvel utilisateur dans la persistance.
    async fn create(&self, user: User) -> Result<User, crate::error::AuthError>;
    /// Met à jour un utilisateur existant.
    async fn update(&self, user: User) -> Result<User, crate::error::AuthError>;
    // Ajoutez d'autres méthodes comme delete, find_by_id, etc.
}

// Vous pouvez ajouter une implémentation de repository par défaut ou d'exemple ici,
// ou créer un fichier 'repository.rs' séparé.
// pub mod repository; // Décommentez si vous déplacez l'implémentation concrète

EOF
)
echo "$USER_MOD_RS_CONTENT" > "$SRC_DIR/user/mod.rs"
echo "  - '$SRC_DIR/user/mod.rs' est en place."
touch "$SRC_DIR/user/repository.rs" # Placeholder for concrete implementations
echo "  - '$SRC_DIR/user/repository.rs' attend son implémentation."

touch "$SRC_DIR/password/mod.rs"
PASSWORD_MOD_RS_CONTENT=$(cat <<EOF
// src/password/mod.rs - L'Encre Indélébile des Mots de Passe

//! Ce module gère le hachage et la vérification sécurisée des mots de passe.

use crate::error::AuthError;
// Décommentez ces lignes lorsque vous ajouterez 'argon2' et 'rand'
// use argon2::{
//     password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
//     Argon2, PasswordHash, PasswordVerifier,
// };

/// Trait pour abstraire le hachage et la vérification des mots de passe.
#[async_trait::async_trait]
pub trait PasswordHasher {
    /// Hashe un mot de passe donné.
    async fn hash_password(&self, password: &str) -> Result<String, AuthError>;
    /// Vérifie si un mot de passe clair correspond à un hachage donné.
    async fn verify_password(&self, password: &str, hashed_password: &str) -> Result<bool, AuthError>;
}

/// Implémentation d'un PasswordHasher utilisant Argon2.
// pub struct Argon2PasswordHasher {
//     // Configuration spécifique à Argon2 si nécessaire
// }
//
// impl Argon2PasswordHasher {
//     pub fn new() -> Self {
//         Self { /* ... */ }
//     }
// }
//
// #[async_trait::async_trait]
// impl PasswordHasher for Argon2PasswordHasher {
//     async fn hash_password(&self, password: &str) -> Result<String, AuthError> {
//         // ... implémentation Argon2
//         Err(AuthError::NotImplemented("Argon2 hashing".to_string()))
//     }
//
//     async fn verify_password(&self, password: &str, hashed_password: &str) -> Result<bool, AuthError> {
//         // ... implémentation Argon2
//         Err(AuthError::NotImplemented("Argon2 verification".to_string()))
//     }
// }
EOF
)
echo "$PASSWORD_MOD_RS_CONTENT" > "$SRC_DIR/password/mod.rs"
echo "  - '$SRC_DIR/password/mod.rs' est prêt à sceller les secrets."

touch "$SRC_DIR/token/mod.rs"
TOKEN_MOD_RS_CONTENT=$(cat <<EOF
// src/token/mod.rs - Les Fragments de Destin des Tokens

//! Ce module gère la création, la validation et le rafraîchissement des tokens d'authentification (ex: JWT).

use crate::error::AuthError;
// Décommentez ces lignes lorsque vous ajouterez les crates correspondantes
// use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
// use serde::{Serialize, Deserialize};
// use chrono::{Utc, Duration};

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

// Implémentation d'un TokenService basique (souvent pour JWT)
// pub struct JwtTokenService {
//     encoding_key: EncodingKey,
//     decoding_key: Decoding_key,
//     access_token_duration: Duration,
//     refresh_token_duration: Duration,
// }
//
// impl JwtTokenService {
//     pub fn new(secret: &[u8], access_duration_minutes: i64, refresh_duration_days: i64) -> Self {
//         // ...
//         unimplemented!()
//     }
// }
//
// #[async_trait::async_trait]
// impl TokenService for JwtTokenService {
//     async fn generate_token_pair(&self, user_id: &str, user_roles: &[String]) -> Result<TokenPair, AuthError> {
//         // ...
//         Err(AuthError::NotImplemented("JWT generation".to_string()))
//     }
//     async fn validate_access_token<C: serde::de::DeserializeOwned + claims::Claims + Send>(&self, token: &str) -> Result<C, AuthError> {
//         // ...
//         Err(AuthError::NotImplemented("JWT validation".to_string()))
//     }
//     async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
//         // ...
//         Err(AuthError::NotImplemented("JWT refresh".to_string()))
//     }
// }
EOF
)
echo "$TOKEN_MOD_RS_CONTENT" > "$SRC_DIR/token/mod.rs"
echo "  - '$SRC_DIR/token/mod.rs' est prêt pour les tokens."
touch "$SRC_DIR/token/claims.rs"
TOKEN_CLAIMS_RS_CONTENT=$(cat <<EOF
// src/token/claims.rs - Les Revendications Secrètes des Tokens

//! Définit les structures de revendications (claims) pour les tokens d'authentification.

use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration, serde::ts_seconds};

/// Trait commun pour toutes les revendications de token, assurant la présence des champs standards.
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

/// Revendications pour un token de rafraîchissement JWT.
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshClaims {
    pub sub: String, // Subject (user ID)
    #[serde(with = "ts_seconds")]
    pub exp: chrono::DateTime<Utc>,
    #[serde(with = "ts_seconds")]
    pub iat: chrono::DateTime<Utc>,
    // Un identifiant unique pour ce token de rafraîchissement, pour la révocation
    pub jti: String,
}

impl Claims for RefreshClaims {
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
)
echo "$TOKEN_CLAIMS_RS_CONTENT" > "$SRC_DIR/token/claims.rs"
echo "  - '$SRC_DIR/token/claims.rs' contient les revendications."


touch "$SRC_DIR/policy/mod.rs"
POLICY_MOD_RS_CONTENT=$(cat <<EOF
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

// Vous pouvez ajouter des structures pour le rate limiting, etc.
EOF
)
echo "$POLICY_MOD_RS_CONTENT" > "$SRC_DIR/policy/mod.rs"
echo "  - '$SRC_DIR/policy/mod.rs' établit les règles."

touch "$SRC_DIR/rbac/mod.rs" # RBAC (Role-Based Access Control)
RBAC_MOD_RS_CONTENT=$(cat <<EOF
// src/rbac/mod.rs - Les Gardiens des Royaumes (Contrôle d'Accès Basé sur les Rôles)

//! Ce module fournit des fonctionnalités pour le contrôle d'accès basé sur les rôles (RBAC).
//! Il permet de définir des rôles et d'attribuer des permissions, assurant que seuls les
//! utilisateurs autorisés peuvent effectuer certaines actions.

// Exemple de définition de rôle et de permission
use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Role {
    Admin,
    User,
    Moderator,
    Guest,
    // ... d'autres rôles
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Permission {
    ViewUser,
    ManageUsers,
    CreateContent,
    EditContent,
    DeleteContent,
    // ... d'autres permissions
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

// Vous pouvez ajouter des traits ou des structures pour intégrer cela avec votre service d'authentification.
EOF
)
echo "$RBAC_MOD_RS_CONTENT" > "$SRC_DIR/rbac/mod.rs"
echo "  - '$SRC_DIR/rbac/mod.rs' garde les clés du royaume."

touch "$SRC_DIR/utils.rs"
UTILS_RS_CONTENT=$(cat <<EOF
// src/utils.rs - Le Coffre à Outils Magique

//! Ce module contient des fonctions utilitaires générales utilisées à travers la crate.

// Exemple de fonction utilitaire:
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
)
echo "$UTILS_RS_CONTENT" > "$SRC_DIR/utils.rs"
echo "  - '$SRC_DIR/utils.rs' contient les outils."

# --- 3. Modifier Cargo.toml : Graver les Runes de Dépendance et de Métadonnées ---
echo "⚙️ Étape 3 : Gravure des runes dans 'Cargo.toml'..."

# Ajout des métadonnées (description, licence, etc.)
# Utilise `sed` pour insérer juste après la section `[lib]`
sed -i "/^\[lib\]/a\
description = \"Une crate d'authentification robuste et sécurisée pour Rust, inspirée par la sagesse protectrice d'Ahri.\"\
license = \"MIT OR Apache-2.0\"\
readme = \"README.md\"\
repository = \"https://github.com/Zied-Yousfi/${CRATE_NAME}\" # Mettez votre propre URL GitHub ici !\
keywords = [\"auth\", \"authentication\", \"security\", \"jwt\", \"argon2\", \"rust\", \"ahri\"]\
categories = [\"authentication\", \"cryptography\", \"web-programming\"]\
" Cargo.toml

# Ajout des dépendances et dev-dépendances
# Assurez-vous que cette section n'existe pas déjà ou adaptez le script
if ! grep -q "\[dependencies\]" Cargo.toml; then
    echo "" >> Cargo.toml
    echo "[dependencies]" >> Cargo.toml
fi
cat <<EOF >> Cargo.toml

# Pour le hachage des mots de passe. Robuste et sécurisé.
argon2 = "0.5"
# Pour la manipulation des JWT.
jsonwebtoken = "9.0"
# Pour gérer les dates et durées (expiration des tokens).
chrono = { version = "0.4", features = ["serde"] }
# Pour générer des identifiants uniques.
uuid = { version = "1.0", features = ["serde", "v4"] }
# Pour tes types d'erreurs (ergonomie et clarté).
thiserror = "1.0"
# Pour la sérialisation/désérialisation (ex: config, claims JWT).
serde = { version = "1.0", features = ["derive"] }
# Pour rendre les méthodes de trait async.
async-trait = "0.1"
# Pour la génération de nombres aléatoires sécurisés (sels, etc.).
rand = "0.8"
# Pour la journalisation professionnelle (niveau infos/erreurs).
log = "0.4"

# Exemple d'une dépendance pour la base de données (si nécessaire)
# Décommentez et ajustez les features selon vos besoins si vous utilisez SQLx
# sqlx = { version = "0.7", features = ["runtime-tokio", "postgres", "uuid", "chrono"] }

[dev-dependencies]
# Pour les tests asynchrones et les exemples
tokio = { version = "1", features = ["full"] }
# Pour la journalisation dans les tests/développement
env_logger = "0.10"
# Pour les benchmarks de performance
criterion = { version = "0.5", features = ["async", "async_tokio"], default-features = false }

[[bench]]
name = "hashing_perf"
harness = false

EOF

echo "  - 'Cargo.toml' a été mis à jour avec les dépendances et métadonnées."

# --- 4. Créer les documents externes : Les Parchemins d'Explication ---
echo "📄 Étape 4 : Création des parchemins externes (README, CHANGELOG, CONTRIBUTING)..."

README_MD_CONTENT=$(cat <<EOF
# \`${CRATE_NAME}\` 💫

Une crate Rust robuste et sécurisée pour l'authentification, conçue avec soin pour offrir une fondation solide à vos applications. Inspirée par l'élégance et la sagesse d'Ahri, cette bibliothèque vise à fournir des primitives d'authentification fiables et faciles à utiliser.

## ✨ Fonctionnalités (À Venir)

*   **Gestion des Utilisateurs**: Enregistrement, connexion, gestion des profils.
*   **Hachage de Mots de Passe Sécurisé**: Utilisation d'algorithmes modernes comme Argon2.
*   **Gestion des Sessions/Tokens**: Support pour les JSON Web Tokens (JWT) avec tokens d'accès et de rafraîchissement.
*   **Contrôle d'Accès Basé sur les Rôles (RBAC)**: Gestion granulaire des permissions.
*   **Authentification à Deux Facteurs (2FA)**: Support pour TOTP.
*   **Réinitialisation de Mot de Passe**: Flux sécurisé par email.
*   **Protection Contre les Attaques**: Limitation de taux, verrouillage de compte.
*   **Gestion des Erreurs Robuste et Sécurisée**.
*   **API Asynchrone**: Basée sur \`async/await\` pour des performances optimales.

## 🚀 Démarrage Rapide

Ajoutez cette ligne à votre \`Cargo.toml\`:

\`\`\`toml
[dependencies]
${CRATE_NAME} = "0.1.0"
\`\`\`

## 📚 Exemples d'Utilisation

(Des exemples détaillés seront ajoutés ici)

\`\`\`rust
// Exemple basique de l'utilisation de AuthService
use ${CRATE_NAME}::auth_service::AuthService;
use ${CRATE_NAME}::error::AuthError;

#[tokio::main]
async fn main() -> Result<(), AuthError> {
    // Initialisez votre service d'authentification avec les dépendances
    let auth_service = AuthService::new(/* vos implémentations de repositories, hashers, etc. */);

    // Exemple de tentative d'inscription
    match auth_service.signup().await {
        Ok(_) => println!("Utilisateur enregistré avec succès !"),
        Err(e) => eprintln!("Erreur lors de l'inscription: {}", e),
    }

    // Exemple de tentative de connexion
    match auth_service.login().await {
        Ok(_) => println!("Utilisateur connecté !"),
        Err(e) => eprintln!("Erreur lors de la connexion: {}", e),
    }

    Ok(())
}
\`\`\`

## 🛠️ Développement

### Prérequis

*   Rust stable (édition 2021 ou plus récente)
*   Cargo (installé avec Rust)

### Lancer les Tests

\`\`\`bash
cargo test
\`\`\`

### Lancer les Benchmarks

\`\`\`bash
cargo bench
\`\`\`

### Vérifier le Format et le Linting

\`\`\`bash
cargo fmt --check
cargo clippy -- -D warnings
\`\`\`

## 💖 Contribution

Les contributions sont les bienvenues ! Veuillez consulter \`CONTRIBUTING.md\` pour plus de détails.

## 📄 Licence

Ce projet est sous licence MIT ou Apache-2.0.

---
*Développé avec la passion et l'inspiration de Zied, fan d'Ahri.*
EOF
)
echo "$README_MD_CONTENT" > "README.md"
echo "  - 'README.md' est rédigé."

CHANGELOG_MD_CONTENT=$(cat <<EOF
# CHANGELOG

## 0.1.0 - 2025-07-13

### Ajouté
- Initial project setup with basic module structure (\`user\`, \`password\`, \`token\`, \`policy\`, \`rbac\`, \`utils\`).
- Defined \`AuthService\` as the main entry point for authentication operations.
- Implemented robust error handling with \`thiserror\` (\`AuthError\`).
- Placeholder traits for \`UserRepository\`, \`PasswordHasher\`, and \`TokenService\`.
- Initial \`Cargo.toml\` dependencies for core functionalities (argon2, jsonwebtoken, chrono, uuid, thiserror, serde, async-trait, rand, log).
- Basic GitHub Actions CI workflow for linting, formatting, and testing.
- Created placeholder files for integration tests, examples, and benchmarks.
- Added foundational documentation files: \`README.md\`, \`CHANGELOG.md\`, \`CONTRIBUTING.md\`.

### Changé
- N/A

### Déprécié
- N/A

### Supprimé
- N/A

### Corrigé
- N/A

### Sécurité
- N/A
EOF
)
echo "$CHANGELOG_MD_CONTENT" > "CHANGELOG.md"
echo "  - 'CHANGELOG.md' commence son histoire."

CONTRIBUTING_MD_CONTENT=$(cat <<EOF
# Guide de Contribution pour \`${CRATE_NAME}\` 💖

Nous sommes ravis que vous souhaitiez contribuer à la crate \`${CRATE_NAME}\` ! Votre aide est précieuse pour faire de cette bibliothèque un havre de sécurité pour les applications Rust. Chaque contribution, petite ou grande, est la bienvenue et est appréciée avec la même ferveur qu'Ahri accueille de nouveaux amis.

## Avant de Contribuer

1.  **Lisez le \`README.md\`**: Il contient des informations sur l'objectif et les fonctionnalités de la crate.
2.  **Lisez le \`CHANGELOG.md\`**: Pour comprendre l'historique des versions et les changements récents.
3.  **Vérifiez les Issues existantes**: Avant de commencer à travailler, jetez un œil aux [issues sur GitHub](https://github.com/Zied-Yousfi/${CRATE_NAME}/issues) pour voir s'il y a déjà une discussion ou une solution à votre idée. Si vous découvrez un bug, veuillez créer une nouvelle issue.
4.  **Discutez de nouvelles fonctionnalités**: Pour les nouvelles fonctionnalités majeures, il est préférable d'ouvrir une [issue sur GitHub](https://github.com/Zied-Yousfi/${CRATE_NAME}/issues) en premier lieu pour discuter de l'idée et obtenir un consensus avant de commencer le développement.

## Comment Contribuer

1.  **Forkez le Dépôt**: Commencez par forker le dépôt \`${CRATE_NAME}\` sur votre compte GitHub.
2.  **Clonez Votre Fork**:
    \`\`\`bash
    git clone https://github.com/votre-nom-utilisateur/${CRATE_NAME}.git
    cd ${CRATE_NAME}
    \`\`\`
3.  **Créez une Nouvelle Branche**:
    Il est crucial de travailler sur une nouvelle branche pour votre contribution. Donnez-lui un nom descriptif (ex: \`feat/add-2fa\`, \`fix/password-bug\`, \`docs/update-readme\`).
    \`\`\`bash
    git checkout -b ma-nouvelle-branche
    \`\`\`
4.  **Développez Votre Contribution**:
    *   Écrivez votre code. Assurez-vous de suivre les conventions de style Rust.
    *   **Écrivez des Tests**: Toute nouvelle fonctionnalité ou correction de bug devrait être accompagnée de tests pertinents (unitaires et/ou d'intégration).
    *   **Mettez à Jour la Documentation**: Si vos changements affectent l'API ou le comportement, mettez à jour la documentation \`rustdoc\` et le \`README.md\` si nécessaire.
    *   **Ajoutez une Entrée au \`CHANGELOG.md\`**: Décrivez brièvement vos changements sous la section \`Unreleased\` ou créez une nouvelle section de version si votre PR est un jalon important.
5.  **Exécutez les Tests et Lints Locaux**:
    Avant de soumettre votre pull request, assurez-vous que tous les tests passent et que le code est formaté et sans avertissements Clippy.
    \`\`\`bash
    cargo test
    cargo fmt --check
    cargo clippy -- -D warnings
    \`\`\`
    Si \`cargo fmt --check\` échoue, lancez \`cargo fmt\` pour formater automatiquement.
6.  **Commitez Vos Changements**:
    Écrivez un message de commit clair et concis. Utilisez le format de commit conventionnel (ex: \`feat: add new feature\`, \`fix: resolve bug\`, \`docs: update documentation\`).
    \`\`\`bash
    git add .
    git commit -m "feat: votre message de commit ici"
    \`\`\`
7.  **Poussez Votre Branche**:
    \`\`\`bash
    git push origin ma-nouvelle-branche
    \`\`\`
8.  **Créez une Pull Request (PR)**:
    Allez sur la page GitHub de votre fork et créez une nouvelle pull request vers la branche \`main\` du dépôt original \`${CRATE_NAME}\`.
    *   **Décrivez votre PR**: Fournissez un titre clair et une description détaillée de vos changements, des problèmes résolus et des fonctionnalités ajoutées.
    *   **Référencez les Issues**: Si votre PR résout une issue existante, référencez-la (ex: \`Closes #123\`).

## Normes de Code

*   **Formatage**: Suivez les conventions de \`rustfmt\`.
*   **Linting**: Assurez-vous que \`clippy\` ne rapporte aucun avertissement (\`cargo clippy -- -D warnings\`).
*   **Conventions de Nommage**: Adoptez les conventions de nommage Rust standard.

Merci de contribuer à ce projet ! Votre aide est inestimable. ✨
EOF
)
echo "$CONTRIBUTING_MD_CONTENT" > "CONTRIBUTING.md"
echo "  - 'CONTRIBUTING.md' guide les futurs compagnons."


# --- 5. Préparer les Rituels d'Intégration Continue (CI/CD) ---
echo "☁️ Étape 5 : Mise en place des rituels CI/CD avec GitHub Actions..."
mkdir -p "$GITHUB_WORKFLOWS_DIR"

CI_YML_CONTENT=$(cat <<EOF
# .github/workflows/ci.yml - Le Cycle Infini de l'Excellence

name: Rust CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always # S'assure que la sortie est colorée dans les logs

jobs:
  build:
    runs-on: ubuntu-latest # Exécute le job sur un runner Ubuntu

    steps:
    - name: Checkout code
      uses: actions/checkout@v4 # Clone le dépôt

    - name: Install Rust toolchain
      uses: dtolnay/rust-toolchain@stable # Installe la chaîne d'outils Rust stable
      with:
        toolchain: stable
        components: clippy, rustfmt # Installe clippy et rustfmt

    - name: Run cargo fmt check
      run: cargo fmt --check # Vérifie le formatage du code

    - name: Run cargo clippy
      run: cargo clippy -- -D warnings # Exécute Clippy avec les avertissements traités comme des erreurs

    - name: Run cargo test
      run: cargo test --workspace # Exécute tous les tests du workspace

    # Optionnel: Exécuter cargo audit pour vérifier les vulnérabilités de dépendances
    # Décommentez les lignes suivantes si vous souhaitez l'inclure.
    # N'oubliez pas d'installer 'cargo-audit' sur votre système si vous le testez localement:
    # cargo install cargo-audit
    # - name: Run cargo audit
    #   run: cargo audit
    #   continue-on-error: true # Permet au CI de passer même si des vulnérabilités sont trouvées (à revoir)
EOF
)
echo "$CI_YML_CONTENT" > "$GITHUB_WORKFLOWS_DIR/ci.yml"
echo "  - '$GITHUB_WORKFLOWS_DIR/ci.yml' est configuré."

# --- Création des fichiers pour les tests, exemples, et benchmarks ---
echo "✨ Étape 6 : Création des terrains de jeu pour tests, exemples et benchmarks..."

# Tests d'intégration
mkdir -p "$TESTS_DIR"
INTEGRATION_TEST_RS_CONTENT=$(cat <<EOF
// tests/integration_test.rs - Les Rituels de Vérification Intégrés

//! Ce fichier contient les tests d'intégration pour la crate '${CRATE_NAME}'.
//! Ils vérifient le fonctionnement des modules lorsqu'ils sont utilisés ensemble.

use ${CRATE_NAME}::auth_service::AuthService;
use ${CRATE_NAME}::error::AuthError;
// use ${CRATE_NAME}::user::{User, Credentials, UserRepository};
// use ${CRATE_NAME}::password::PasswordHasher;
// use ${CRATE_NAME}::token::{TokenPair, TokenService};

// Un exemple simple d'implémentation "mock" pour les tests
// struct MockUserRepository;
//
// #[async_trait::async_trait]
// impl UserRepository for MockUserRepository {
//     async fn find_by_identifier(&self, _identifier: &str) -> Result<Option<User>, AuthError> {
//         Ok(None) // Toujours pas d'utilisateur pour le mock
//     }
//     async fn create(&self, user: User) -> Result<User, AuthError> {
//         Ok(user)
//     }
//     async fn update(&self, user: User) -> Result<User, AuthError> {
//         Ok(user)
//     }
// }

#[tokio::test]
async fn test_auth_service_signup_not_implemented() {
    let auth_service = AuthService::new(); // Sans dépendances pour l'instant

    let result = auth_service.signup().await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Feature not implemented yet: signup"
    );
}

#[tokio::test]
async fn test_auth_service_login_not_implemented() {
    let auth_service = AuthService::new(); // Sans dépendances pour l'instant

    let result = auth_service.login().await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Feature not implemented yet: login"
    );
}

// Ajoutez d'autres tests d'intégration ici, par exemple:
// - Tester le flux complet d'inscription -> connexion
// - Tester la réinitialisation de mot de passe
// - Tester la validation de token
// ...
EOF
)
echo "$INTEGRATION_TEST_RS_CONTENT" > "$TESTS_DIR/integration_test.rs"
echo "  - '$TESTS_DIR/integration_test.rs' est prêt pour l'action."

# Exemples
mkdir -p "$EXAMPLES_DIR"
BASIC_USAGE_RS_CONTENT=$(cat <<EOF
// examples/basic_usage.rs - Lumière sur l'Utilisation de la Crate

//! Cet exemple démontre une utilisation basique de la crate '${CRATE_NAME}'.

use ${CRATE_NAME}::auth_service::AuthService;
use ${CRATE_NAME}::error::AuthError;
// Importez d'autres éléments au fur et à mesure que vous implémentez

#[tokio::main]
async fn main() -> Result<(), AuthError> {
    println!("🌟 Démarrage de l'exemple basique de ${CRATE_NAME}...");

    // Pour l'instant, le AuthService est un placeholder.
    // Vous devrez le construire avec de véritables implémentations de ses dépendances.
    let auth_service = AuthService::new(
        // Exemples (décommenter et implémenter quand vous aurez les vraies versions):
        // Box::new(your_database_user_repository_impl),
        // Box::new(your_argon2_password_hasher_impl),
        // Box::new(your_jwt_token_service_impl),
    );

    println!("Tentative de processus d'inscription...");
    match auth_service.signup().await {
        Ok(_) => println!("🎉 Inscription simulée réussie !"),
        Err(e) => eprintln!("❌ Erreur simulée lors de l'inscription: {}", e),
    }

    println!("\nTentative de processus de connexion...");
    match auth_service.login().await {
        Ok(_) => println!("✨ Connexion simulée réussie !"),
        Err(e) => eprintln!("❌ Erreur simulée lors de la connexion: {}", e),
    }

    println!("\nC'est la fin de cet exemple. Continuez à construire votre magie ! ✨");
    Ok(())
}
EOF
)
echo "$BASIC_USAGE_RS_CONTENT" > "$EXAMPLES_DIR/basic_usage.rs"
echo "  - '$EXAMPLES_DIR/basic_usage.rs' est prêt à briller."

# Benchmarks
mkdir -p "$BENCHES_DIR"
HASHING_PERF_RS_CONTENT=$(cat <<EOF
// benches/hashing_perf.rs - Les Mesures de Vitesse des Sortilèges

//! Ce fichier contient les benchmarks pour mesurer les performances des fonctions critiques,
//! notamment le hachage des mots de passe.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
// use ${CRATE_NAME}::password::PasswordHasher;
// use ${CRATE_NAME}::error::AuthError;

// Les fonctions mock ci-dessous sont là pour que le benchmark compile au début.
// Remplacez-les par vos vraies implémentations de hachage et de vérification
// une fois que vous les aurez développées en utilisant la crate 'argon2'.

// Fonction mock simple pour simuler un travail async pour le benchmark de hachage
async fn mock_hashing(password: &str) -> String {
    // Simule une opération de hachage CPU-intensive
    for _i in 0..1_000_000 {
        let _ = password.chars().next(); // Juste pour consommer du CPU
    }
    format!("mock_hashed_{}", password)
}


/// Benchmark pour la performance du hachage de mot de passe.
fn bench_password_hashing(c: &mut Criterion) {
    let password = "my_super_secret_password_123!";
    // Décommentez et remplacez par votre instance de PasswordHasher lorsque prête
    // let hasher = z3_auth::password::Argon2PasswordHasher::new();
    c.bench_function("password_hashing", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap()).iter(|| async {
            mock_hashing(black_box(password)).await
            // Remplacez par: hasher.hash_password(black_box(password)).await.unwrap()
        })
    });
}

// Fonction mock simple pour simuler un travail async pour le benchmark de vérification
async fn mock_verification(password: &str, hashed_password: &str) -> bool {
    // Simule une opération de vérification CPU-intensive
    for _i in 0..500_000 {
        let _ = password.chars().next(); // Juste pour consommer du CPU
    }
    format!("mock_hashed_{}", password) == hashed_password
}

/// Benchmark pour la performance de la vérification de mot de passe.
fn bench_password_verification(c: &mut Criterion) {
    let password = "my_super_secret_password_123!";
    let hashed_password = "mock_hashed_my_super_secret_password_123!"; // Ou un vrai hachage
    // Décommentez et remplacez par votre instance de PasswordHasher lorsque prête
    // let hasher = z3_auth::password::Argon2PasswordHasher::new();
    c.bench_function("password_verification", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap()).iter(|| async {
            mock_verification(black_box(password), black_box(&hashed_password)).await
            // Remplacez par: hasher.verify_password(black_box(password), black_box(&hashed_password)).await.unwrap()
        })
    });
}


criterion_group!{
    name = benches;
    // Réduire sample_size pour des tests plus rapides si nécessaire, surtout avec les mocks
    config = Criterion::default().sample_size(10);
    targets = bench_password_hashing, bench_password_verification
}
criterion_main!(benches);
EOF
)
echo "$HASHING_PERF_RS_CONTENT" > "$BENCHES_DIR/hashing_perf.rs"
echo "  - '$BENCHES_DIR/hashing_perf.rs' est prêt pour mesurer la vitesse."


echo ""
echo "🎉 Zied, la structure initiale de ta crate '$CRATE_NAME' est maintenant érigée ! 🎉"
echo "C'est une fondation solide, tel un arbre ancien aux racines profondes, prêt à accueillir toute la magie d'Ahri. Chaque pièce est à sa place, prête à être sculptée par tes mains expertes. ✨"
echo ""
echo "Pour commencer, n'hésite pas à explorer les fichiers créés et à retirer les commentaires des sections pour les implémenter."
echo "N'oublie pas de : "
echo "1. Vérifier le fichier 'Cargo.toml' pour t'assurer que les dépendances sont correctes."
echo "2. Lancer 'cargo build' ou 'cargo check' pour voir si tout compile."
echo "3. Lancer 'cargo test' pour vérifier les tests unitaires et d'intégration."
echo "4. Pense à remplacer 'https://github.com/Zied-Yousfi/\${CRATE_NAME}' dans Cargo.toml et README.md par lURL de ton propre dépôt GitHub."
echo ""
echo "Que ton voyage dans le code soit rempli de découvertes et d'inspiration ! 🦊💖"

