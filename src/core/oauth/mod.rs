//! OAuth2 core module for authentication and authorization.
//!
//! This module provides abstractions and implementations for handling OAuth2 flows,
//! including generating authorization URLs, exchanging codes for tokens, fetching user info,
//! and refreshing tokens. It is designed to support multiple providers and extensible flows.
//!
//! # Modules
//!
//! - `manager`: Contains the logic for managing OAuth2 operations and provider-specific details.
//! - `store`: Defines types and storage mechanisms for OAuth2 tokens, user info, and providers.
//!
//! # Traits
//!
//! - [`OAuth2Service`]: The main trait for interacting with OAuth2 providers.

use async_trait::async_trait;

#[async_trait]

/// Trait for handling OAuth2 authentication and authorization flows.
///
/// Implementors of this trait provide methods for generating authorization URLs,
/// exchanging authorization codes for tokens, fetching user information, and refreshing tokens.
/// This trait is designed to be provider-agnostic and extensible for various OAuth2 providers.
///
/// # Example
///
/// ```rust,ignore
/// let url = service.generate_auth_url(provider, state, Some(vec!["email".to_string()])).await?;
/// ```
pub trait OAuth2Service {
    /// Generates an authorization URL for the specified OAuth2 provider.
    ///
    /// This method constructs the URL to which users should be redirected to begin the OAuth2 flow.
    /// It includes the necessary parameters for CSRF protection and can request additional scopes.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider for which to generate the authorization URL.
    /// * `state` - A unique state string for CSRF protection.
    /// * `scopes` - Optional list of additional scopes to request beyond the provider's defaults.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` - The generated authorization URL.
    /// * `Err(AuthError)` - If URL generation fails due to configuration or provider errors.
    async fn generate_auth_url(
        &self,
        provider: store::OAuth2Provider,
        state: &str,
        scopes: Option<Vec<String>>,
    ) -> Result<String, crate::AuthError>;

    /// Exchanges an authorization code for an access token with the OAuth2 provider.
    ///
    /// This method is called after the user has authorized the application and the provider
    /// has redirected back with an authorization code. It verifies the state and requests
    /// an access token from the provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider to exchange the code with.
    /// * `code` - The authorization code received from the provider.
    /// * `state` - The state parameter for CSRF protection and verification.
    ///
    /// # Returns
    ///
    /// * `Ok(OAuth2Token)` - The access token and related information.
    /// * `Err(AuthError)` - If the exchange fails due to invalid code, state, or provider error.
    async fn exchange_code_for_token(
        &self,
        provider: store::OAuth2Provider,
        code: &str,
        state: &str,
    ) -> Result<store::OAuth2Token, crate::AuthError>;

    /// Fetches user information from the OAuth2 provider using the provided access token.
    ///
    /// This method retrieves user profile data from the provider's user info endpoint.
    ///
    /// # Arguments
    ///
    /// * `token` - The OAuth2 token to use for authentication when fetching user info.
    ///
    /// # Returns
    ///
    /// * `Ok(OAuth2UserInfo)` - The user's profile information as returned by the provider.
    /// * `Err(AuthError)` - If fetching user info fails due to invalid token or provider error.
    async fn fetch_user_info(
        &self,
        token: &store::OAuth2Token,
    ) -> Result<store::OAuth2UserInfo, crate::AuthError>;

    /// Refreshes an access token using a refresh token.
    ///
    /// This method requests a new access token from the provider using a valid refresh token.
    /// Useful for maintaining long-lived sessions without requiring user re-authentication.
    ///
    /// # Arguments
    ///
    /// * `token` - The OAuth2 token containing the refresh token.
    ///
    /// # Returns
    ///
    /// * `Ok(OAuth2Token)` - The new access token and related information.
    /// * `Err(AuthError)` - If refreshing fails due to invalid token or provider error.
    async fn refresh_token(
        &self,
        token: &store::OAuth2Token,
    ) -> Result<store::OAuth2Token, crate::AuthError>;
}

/// OAuth2 manager module: contains logic for managing provider-specific operations.
pub mod manager;

/// OAuth2 store module: defines types and storage for tokens, user info, and providers.
pub mod store;
