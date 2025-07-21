//! OAuth2 provider, token, user info, config, and session types for authentication flows.
//!
//! This module defines enums and structs for representing OAuth2 providers, tokens, user information,
//! configuration, and session state. It also provides utility methods for working with these types.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Supported OAuth2 providers for authentication.
///
/// This enum lists all external providers supported by the authentication system.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum OAuth2Provider {
    /// Google OAuth2 provider.
    Google,
    /// GitHub OAuth2 provider.
    GitHub,
    /// Discord OAuth2 provider.
    Discord,
    /// Microsoft OAuth2 provider.
    Microsoft,
}

impl OAuth2Provider {
    /// Returns the display name of the provider as a string.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Google => "Google",
            Self::GitHub => "GitHub",
            Self::Discord => "Discord",
            Self::Microsoft => "Microsoft",
        }
    }

    /// Returns the default OAuth2 scopes required for the provider.
    pub fn default_scopes(&self) -> Vec<&'static str> {
        match self {
            Self::Google => vec!["openid", "email", "profile"],
            Self::GitHub => vec!["user:email"],
            Self::Discord => vec!["identify", "email"],
            Self::Microsoft => vec!["openid", "email", "profile"],
        }
    }
}

/// Represents an OAuth2 token, including access and refresh tokens, expiration, and provider info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Token {
    /// The access token string.
    pub access_token: String,
    /// The optional refresh token string.
    pub refresh_token: Option<String>,
    /// The expiration time of the access token, if available.
    pub expires_at: Option<SystemTime>,
    /// The type of token (usually "Bearer").
    pub token_type: String,
    /// The scope of the token, if provided.
    pub scope: Option<String>,
    /// The OAuth2 provider that issued the token.
    pub provider: OAuth2Provider,
    /// The time the token was created.
    pub created_at: SystemTime,
}

impl OAuth2Token {
    /// Returns true if the token is expired, false otherwise.
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| SystemTime::now() > exp)
            .unwrap_or(false)
    }

    /// Returns true if the token will expire within the given threshold (in seconds).
    ///
    /// # Arguments
    ///
    /// * `threshold_secs` - Number of seconds to check for imminent expiration.
    pub fn expires_soon(&self, threshold_secs: u64) -> bool {
        self.expires_at
            .map(|exp| {
                SystemTime::now()
                    .duration_since(exp)
                    .map(|d| d.as_secs() < threshold_secs)
                    .unwrap_or(true)
            })
            .unwrap_or(false)
    }
}

/// Represents user information returned by an OAuth2 provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2UserInfo {
    /// The OAuth2 provider.
    pub provider: OAuth2Provider,
    /// The unique user ID from the provider.
    pub provider_user_id: String,
    /// The user's email address, if available.
    pub email: Option<String>,
    /// The user's display name, if available.
    pub name: Option<String>,
    /// The user's avatar URL, if available.
    pub avatar_url: Option<String>,
    /// Whether the user's email is verified, if available.
    pub verified_email: Option<bool>,
    /// The user's locale, if available.
    pub locale: Option<String>,
    /// The time the user info was last updated.
    pub updated_at: SystemTime,
    /// The raw user info data as returned by the provider, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<serde_json::Value>,
}

/// Configuration for OAuth2 authentication with a provider.
#[derive(Debug, Clone)]
pub struct OAuth2Config {
    /// The OAuth2 client ID.
    pub client_id: String,
    /// The OAuth2 client secret.
    pub client_secret: String,
    /// The redirect URI for OAuth2 callbacks.
    pub redirect_uri: String,
    /// Additional scopes to request during authentication.
    pub additional_scopes: Vec<String>,
}

impl OAuth2Config {
    /// Returns the authorization URL for the given provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider.
    pub fn auth_url(&self, provider: OAuth2Provider) -> &'static str {
        match provider {
            OAuth2Provider::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            OAuth2Provider::GitHub => "https://github.com/login/oauth/authorize",
            OAuth2Provider::Discord => "https://discord.com/api/oauth2/authorize",
            OAuth2Provider::Microsoft => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
            }
        }
    }

    /// Returns the token endpoint URL for the given provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider.
    pub fn token_url(&self, provider: OAuth2Provider) -> &'static str {
        match provider {
            OAuth2Provider::Google => "https://oauth2.googleapis.com/token",
            OAuth2Provider::GitHub => "https://github.com/login/oauth/access_token",
            OAuth2Provider::Discord => "https://discord.com/api/oauth2/token",
            OAuth2Provider::Microsoft => {
                "https://login.microsoftonline.com/common/oauth2/v2.0/token"
            }
        }
    }

    /// Returns the user info endpoint URL for the given provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider.
    pub fn user_info_url(&self, provider: OAuth2Provider) -> &'static str {
        match provider {
            OAuth2Provider::Google => "https://www.googleapis.com/oauth2/v2/userinfo",
            OAuth2Provider::GitHub => "https://api.github.com/user",
            OAuth2Provider::Discord => "https://discord.com/api/users/@me",
            OAuth2Provider::Microsoft => "https://graph.microsoft.com/v1.0/me",
        }
    }
}

/// Represents an OAuth2 session, including state, provider, PKCE verifier, and timing info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Session {
    /// The session state string (used for CSRF protection).
    pub state: String,
    /// The OAuth2 provider for this session.
    pub provider: OAuth2Provider,
    /// The PKCE verifier string, if used.
    pub pkce_verifier: Option<String>,
    /// The time the session was created.
    pub created_at: SystemTime,
    /// The time the session expires.
    pub expires_at: SystemTime,
}
