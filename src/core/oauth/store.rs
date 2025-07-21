use serde::{Deserialize, Serialize};
use std::time::SystemTime;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum OAuth2Provider {
    Google,
    GitHub,
    Discord,
    Microsoft,
}

impl OAuth2Provider {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Google => "Google",
            Self::GitHub => "GitHub",
            Self::Discord => "Discord",
            Self::Microsoft => "Microsoft",
        }
    }

    pub fn default_scopes(&self) -> Vec<&'static str> {
        match self {
            Self::Google => vec!["openid", "email", "profile"],
            Self::GitHub => vec!["user:email"],
            Self::Discord => vec!["identify", "email"],
            Self::Microsoft => vec!["openid", "email", "profile"],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Token {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<SystemTime>,
    pub token_type: String,
    pub scope: Option<String>,
    pub provider: OAuth2Provider,
    pub created_at: SystemTime,
}

impl OAuth2Token {
    pub fn is_expired(&self) -> bool {
        self.expires_at
            .map(|exp| SystemTime::now() > exp)
            .unwrap_or(false)
    }

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2UserInfo {
    pub provider: OAuth2Provider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
    pub verified_email: Option<bool>,
    pub locale: Option<String>,
    pub updated_at: SystemTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_data: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct OAuth2Config {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub additional_scopes: Vec<String>,
}

impl OAuth2Config {
    pub fn auth_url(&self, provider: OAuth2Provider) -> &'static str {
        match provider {
            OAuth2Provider::Google => "https://accounts.google.com/o/oauth2/v2/auth",
            OAuth2Provider::GitHub => "https://github.com/login/oauth/authorize",
            OAuth2Provider::Discord => "https://discord.com/api/oauth2/authorize",
            OAuth2Provider::Microsoft => "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        }
    }

    pub fn token_url(&self, provider: OAuth2Provider) -> &'static str {
        match provider {
            OAuth2Provider::Google => "https://oauth2.googleapis.com/token",
            OAuth2Provider::GitHub => "https://github.com/login/oauth/access_token",
            OAuth2Provider::Discord => "https://discord.com/api/oauth2/token",
            OAuth2Provider::Microsoft => "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        }
    }

    pub fn user_info_url(&self, provider: OAuth2Provider) -> &'static str {
        match provider {
            OAuth2Provider::Google => "https://www.googleapis.com/oauth2/v2/userinfo",
            OAuth2Provider::GitHub => "https://api.github.com/user",
            OAuth2Provider::Discord => "https://discord.com/api/users/@me",
            OAuth2Provider::Microsoft => "https://graph.microsoft.com/v1.0/me",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuth2Session {
    pub state: String,
    pub provider: OAuth2Provider,
    pub pkce_verifier: Option<String>,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}
