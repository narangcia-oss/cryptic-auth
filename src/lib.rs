// src/lib.rs - La Porte Principale de l'Authentification

//! Une crate d'authentification robuste et sécurisée, inspirée par la sagesse d'Ahri.
//! Elle fournit des outils pour la gestion des utilisateurs, le hachage des mots de passe,
//! la gestion des sessions et des tokens, et bien plus encore.

// Rendre les modules publics pour qu'ils soient accessibles aux utilisateurs de la crate
pub mod auth_service;
pub mod error;
pub mod password;
pub mod policy;
pub mod rbac; // Module optionnel pour le contrôle d'accès basé sur les rôles
pub mod token;
pub mod user;
pub mod utils;

// Réexporter les éléments clés pour une utilisation plus facile
pub use auth_service::AuthService;
pub use error::AuthError;

// Vous pouvez ajouter d'autres 'use' ici au fur et à mesure que votre crate grandit
// Par exemple:
// pub use user::{User, Credentials};
// pub use token::TokenPair;
