use async_trait::async_trait;

#[async_trait]
pub trait OAuth2Service {
    /// Generates an authorization URL for the specified provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider to generate the URL for.
    /// * `state` - A state parameter for CSRF protection.
    /// * `scopes` - Optional additional scopes beyond the default ones.
    ///
    /// # Returns
    ///
    /// * `Ok(String)` containing the authorization URL if successful.
    /// * `Err(AuthError)` if generating the URL fails.
    async fn generate_auth_url(
        &self,
        provider: store::OAuth2Provider,
        state: &str,
        scopes: Option<Vec<String>>,
    ) -> Result<String, crate::AuthError>;

    /// Exchanges an authorization code for an access token.
    ///
    /// # Arguments
    ///
    /// * `provider` - The OAuth2 provider.
    /// * `code` - The authorization code received from the provider.
    /// * `state` - The state parameter for verification.
    ///
    /// # Returns
    ///
    /// * `Ok(OAuth2Token)` containing the token if successful.
    /// * `Err(AuthError)` if the token exchange fails.
    async fn exchange_code_for_token(
        &self,
        provider: store::OAuth2Provider,
        code: &str,
        state: &str,
    ) -> Result<store::OAuth2Token, crate::AuthError>;

    /// Fetches user information from the OAuth2 provider using the provided token.
    ///
    /// # Arguments
    ///
    /// * `token` - The OAuth2 token to use for fetching user info.
    ///
    /// # Returns
    ///
    /// * `Ok(OAuth2UserInfo)` containing user information if successful.
    /// * `Err(AuthError)` if fetching user info fails.
    async fn fetch_user_info(
        &self,
        token: &store::OAuth2Token,
    ) -> Result<store::OAuth2UserInfo, crate::AuthError>;

    /// Refreshes an access token using a refresh token.
    ///
    /// # Arguments
    ///
    /// * `token` - The OAuth2 token containing the refresh token.
    ///
    /// # Returns
    ///
    /// * `Ok(OAuth2Token)` containing the new token if successful.
    /// * `Err(AuthError)` if refreshing the token fails.
    async fn refresh_token(
        &self,
        token: &store::OAuth2Token,
    ) -> Result<store::OAuth2Token, crate::AuthError>;
}

pub mod manager;
pub mod store;
