use async_trait::async_trait;

#[async_trait]
pub trait OauthManager {
    /// Fetches the OAuth2 token for a given provider.
    ///
    /// # Arguments
    ///
    /// * `provider` - The name of the OAuth2 provider (e.g., "google", "github").
    ///
    /// # Returns
    ///
    /// * `Ok(OAuth2Token)` containing the token if successful.
    /// * `Err(OAuth2Error)` if fetching the token fails.
    async fn fetch_token(&self, provider: &str) -> Result<store::OAuth2Token, crate::AuthError>;

    /// Fetches user information from the OAuth2 provider using the provided token.
    ///
    /// # Arguments
    ///
    /// * `token` - The OAuth2 token to use for fetching user info.
    ///
    /// # Returns
    ///
    /// * `Ok(OAuth2UserInfo)` containing user information if successful.
    /// * `Err(OAuth2Error)` if fetching user info fails.
    async fn fetch_user_info(
        &self,
        token: &store::OAuth2Token,
    ) -> Result<store::OAuth2UserInfo, crate::AuthError>;
}

pub mod store;
