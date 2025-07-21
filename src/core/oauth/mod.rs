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

use async_trait::async_trait;
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
    pub id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub raw: serde_json::Value,
}

/// Configuration for an OAuth2 provider.
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub user_info_url: String,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
}

/// Errors that can occur during OAuth2 operations.
#[derive(Debug, thiserror::Error)]
pub enum OAuth2Error {
    #[error("Network error: {0}")]
    Network(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Provider error: {0}")]
    Provider(String),
    #[error("Token exchange failed: {0}")]
    TokenExchange(String),
    #[error("User info fetch failed: {0}")]
    UserInfo(String),
    #[error("Other error: {0}")]
    Other(String),
}

/// Trait for a generic OAuth2 provider implementation.
#[async_trait]
pub trait OAuth2Provider: Send + Sync {
    /// Returns the provider's configuration.
    fn config(&self) -> &OAuth2Config;

    /// Generates the authorization URL for the provider.
    fn authorization_url(&self, state: &str) -> String;

    /// Exchanges an authorization code for an access token.
    async fn exchange_code(&self, code: &str) -> Result<OAuth2Token, OAuth2Error>;

    /// Fetches user info using the access token.
    async fn fetch_user_info(&self, token: &OAuth2Token) -> Result<OAuth2UserInfo, OAuth2Error>;
}

// Example: Provider registration (add your providers here)
// pub struct GoogleProvider { ... }
// impl OAuth2Provider for GoogleProvider { ... }

// Add more providers by implementing OAuth2Provider for your struct.
