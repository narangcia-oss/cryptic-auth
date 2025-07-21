//! OAuth2 Manager Implementation
//!
//! This module provides the concrete implementation of the OAuth2Service trait
//! using the `oauth2` and `reqwest` crates for handling OAuth2 authentication flows.

use async_trait::async_trait;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields,
    RedirectUrl, RefreshToken, Scope, StandardTokenResponse, TokenResponse, TokenUrl,
    basic::BasicClient, basic::BasicTokenType,
};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::time::SystemTime;

use super::OAuth2Service;
use super::store::{OAuth2Config, OAuth2Provider, OAuth2Token, OAuth2UserInfo};
use crate::AuthError;

type OAuth2TokenResponse = StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>;

/// OAuth2 Manager that implements the OAuth2Service trait
pub struct OAuth2Manager {
    configs: HashMap<OAuth2Provider, OAuth2Config>,
    http_client: Client,
}

impl OAuth2Manager {
    /// Creates a new OAuth2Manager with the provided configurations
    ///
    /// # Arguments
    ///
    /// * `configs` - A map of OAuth2Provider to OAuth2Config
    ///
    /// # Returns
    ///
    /// A new OAuth2Manager instance
    pub fn new(configs: HashMap<OAuth2Provider, OAuth2Config>) -> Self {
        Self {
            configs,
            http_client: Client::new(),
        }
    }

    /// Gets the OAuth2 client for a given provider
    fn get_client(&self, provider: OAuth2Provider) -> Result<BasicClient, AuthError> {
        let config = self.configs.get(&provider).ok_or_else(|| {
            AuthError::ConfigError(format!("No config found for provider: {:?}", provider))
        })?;

        let auth_url = AuthUrl::new(config.auth_url(provider).to_string())
            .map_err(|e| AuthError::ConfigError(format!("Invalid auth URL: {}", e)))?;

        let token_url = TokenUrl::new(config.token_url(provider).to_string())
            .map_err(|e| AuthError::ConfigError(format!("Invalid token URL: {}", e)))?;

        let client = BasicClient::new(ClientId::new(config.client_id.clone()))
            .set_client_secret(ClientSecret::new(config.client_secret.clone()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(
                RedirectUrl::new(config.redirect_uri.clone())
                    .map_err(|e| AuthError::ConfigError(format!("Invalid redirect URI: {}", e)))?,
            );

        Ok(client)
    }

    /// Parses user information from the provider response
    async fn parse_user_info(
        &self,
        provider: OAuth2Provider,
        response_body: Value,
    ) -> Result<OAuth2UserInfo, AuthError> {
        let now = SystemTime::now();

        match provider {
            OAuth2Provider::Google => {
                let email = response_body["email"].as_str().map(|s| s.to_string());
                let name = response_body["name"].as_str().map(|s| s.to_string());
                let avatar_url = response_body["picture"].as_str().map(|s| s.to_string());
                let verified_email = response_body["verified_email"].as_bool();
                let locale = response_body["locale"].as_str().map(|s| s.to_string());
                let provider_user_id = response_body["id"]
                    .as_str()
                    .ok_or_else(|| AuthError::OAuthInvalidResponse("Missing user ID".to_string()))?
                    .to_string();

                Ok(OAuth2UserInfo {
                    provider,
                    provider_user_id,
                    email,
                    name,
                    avatar_url,
                    verified_email,
                    locale,
                    updated_at: now,
                    raw_data: Some(response_body),
                })
            }
            OAuth2Provider::GitHub => {
                let name = response_body["name"].as_str().map(|s| s.to_string());
                let avatar_url = response_body["avatar_url"].as_str().map(|s| s.to_string());
                let provider_user_id = response_body["id"]
                    .as_u64()
                    .ok_or_else(|| AuthError::OAuthInvalidResponse("Missing user ID".to_string()))?
                    .to_string();

                // GitHub requires a separate API call for email
                let email = if let Some(email_str) = response_body["email"].as_str() {
                    if !email_str.is_empty() {
                        Some(email_str.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                };

                Ok(OAuth2UserInfo {
                    provider,
                    provider_user_id,
                    email,
                    name,
                    avatar_url,
                    verified_email: None,
                    locale: None,
                    updated_at: now,
                    raw_data: Some(response_body),
                })
            }
            OAuth2Provider::Discord => {
                let email = response_body["email"].as_str().map(|s| s.to_string());
                let name = response_body["username"].as_str().map(|s| s.to_string());
                let avatar = response_body["avatar"].as_str();
                let provider_user_id = response_body["id"]
                    .as_str()
                    .ok_or_else(|| AuthError::OAuthInvalidResponse("Missing user ID".to_string()))?
                    .to_string();

                let avatar_url = if let Some(avatar_hash) = avatar {
                    Some(format!(
                        "https://cdn.discordapp.com/avatars/{}/{}.png",
                        provider_user_id, avatar_hash
                    ))
                } else {
                    None
                };

                let verified_email = response_body["verified"].as_bool();
                let locale = response_body["locale"].as_str().map(|s| s.to_string());

                Ok(OAuth2UserInfo {
                    provider,
                    provider_user_id,
                    email,
                    name,
                    avatar_url,
                    verified_email,
                    locale,
                    updated_at: now,
                    raw_data: Some(response_body),
                })
            }
            OAuth2Provider::Microsoft => {
                let email = response_body["mail"]
                    .as_str()
                    .or_else(|| response_body["userPrincipalName"].as_str())
                    .map(|s| s.to_string());
                let name = response_body["displayName"].as_str().map(|s| s.to_string());
                let provider_user_id = response_body["id"]
                    .as_str()
                    .ok_or_else(|| AuthError::OAuthInvalidResponse("Missing user ID".to_string()))?
                    .to_string();

                Ok(OAuth2UserInfo {
                    provider,
                    provider_user_id,
                    email,
                    name,
                    avatar_url: None, // Microsoft Graph doesn't provide avatar URL directly
                    verified_email: None,
                    locale: None,
                    updated_at: now,
                    raw_data: Some(response_body),
                })
            }
        }
    }
}

#[async_trait]
impl OAuth2Service for OAuth2Manager {
    async fn generate_auth_url(
        &self,
        provider: OAuth2Provider,
        state: &str,
        scopes: Option<Vec<String>>,
    ) -> Result<String, AuthError> {
        let client = self.get_client(provider)?;

        let config = self.configs.get(&provider).unwrap();
        let mut all_scopes = provider
            .default_scopes()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();

        if let Some(additional_scopes) = scopes {
            all_scopes.extend(additional_scopes);
        }
        all_scopes.extend(config.additional_scopes.clone());

        let mut auth_request = client.authorize_url(|| CsrfToken::new(state.to_string()));

        for scope in all_scopes {
            auth_request = auth_request.add_scope(Scope::new(scope));
        }

        let (auth_url, _csrf_token) = auth_request.url();
        Ok(auth_url.to_string())
    }

    async fn exchange_code_for_token(
        &self,
        provider: OAuth2Provider,
        code: &str,
        _state: &str,
    ) -> Result<OAuth2Token, AuthError> {
        let client = self.get_client(provider)?;

        let token_result = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| AuthError::OAuthTokenExchange(format!("Token exchange failed: {}", e)))?;

        let access_token = token_result.access_token().secret().clone();
        let refresh_token = token_result.refresh_token().map(|rt| rt.secret().clone());
        let expires_at = token_result
            .expires_in()
            .map(|duration| SystemTime::now() + duration);
        let token_type = token_result.token_type().as_ref().to_string();
        let scope = token_result.scopes().map(|scopes| {
            scopes
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        });

        Ok(OAuth2Token {
            access_token,
            refresh_token,
            expires_at,
            token_type,
            scope,
            provider,
            created_at: SystemTime::now(),
        })
    }

    async fn fetch_user_info(&self, token: &OAuth2Token) -> Result<OAuth2UserInfo, AuthError> {
        let config = self.configs.get(&token.provider).ok_or_else(|| {
            AuthError::ConfigError(format!(
                "No config found for provider: {:?}",
                token.provider
            ))
        })?;

        let user_info_url = config.user_info_url(token.provider);

        let response = self
            .http_client
            .get(user_info_url)
            .bearer_auth(&token.access_token)
            .send()
            .await
            .map_err(|e| AuthError::OAuthNetwork(format!("Failed to fetch user info: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthError::OAuthUserInfo(format!(
                "User info request failed with status: {}",
                response.status()
            )));
        }

        let response_body: Value = response.json().await.map_err(|e| {
            AuthError::OAuthInvalidResponse(format!("Invalid JSON response: {}", e))
        })?;

        self.parse_user_info(token.provider, response_body).await
    }

    async fn refresh_token(&self, token: &OAuth2Token) -> Result<OAuth2Token, AuthError> {
        let client = self.get_client(token.provider)?;

        let refresh_token = token.refresh_token.as_ref().ok_or_else(|| {
            AuthError::OAuthTokenExchange("No refresh token available".to_string())
        })?;

        let token_result = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.clone()))
            .request_async(async_http_client)
            .await
            .map_err(|e| AuthError::OAuthTokenExchange(format!("Token refresh failed: {}", e)))?;

        let access_token = token_result.access_token().secret().clone();
        let new_refresh_token = token_result
            .refresh_token()
            .map(|rt| rt.secret().clone())
            .or_else(|| token.refresh_token.clone());
        let expires_at = token_result
            .expires_in()
            .map(|duration| SystemTime::now() + duration);
        let token_type = token_result.token_type().as_ref().to_string();
        let scope = token_result
            .scopes()
            .map(|scopes| {
                scopes
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .or_else(|| token.scope.clone());

        Ok(OAuth2Token {
            access_token,
            refresh_token: new_refresh_token,
            expires_at,
            token_type,
            scope,
            provider: token.provider,
            created_at: SystemTime::now(),
        })
    }
}

impl Default for OAuth2Manager {
    fn default() -> Self {
        Self::new(HashMap::new())
    }
}
