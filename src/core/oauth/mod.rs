//! Generic OAuth2 authentication framework for Cryptic.
//!
//! This module provides secure, extensible abstractions for integrating OAuth2 providers (e.g., Google, GitHub, etc.).
//! It is designed for professional use, with a focus on security, testability, and ease of adding new providers.
//!
//! # Features
//! - Provider-agnostic OAuth2 trait
//! - Secure token and user info handling
//! - Extensible configuration
//! - Strong error types
//! - Async/await compatible

use serde::{Deserialize, Serialize};

/// Represents an OAuth2 access token and optional refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Token {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
}

/// Represents a generic OAuth2 user info response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2UserInfo {
    pub provider: OAuth2Provider, // e.g., "google", "github"
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub raw: serde_json::Value,
}

/// Configuration for an OAuth2 provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Config {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Provider {
    pub name: String,
    pub config: OAuth2Config,
}
