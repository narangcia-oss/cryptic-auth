/// Configuration variables required for the authentication service.
///
/// This struct holds the secret key and token expiration settings used by the authentication system.
///
/// # Fields
///
/// - `secret_key`: The cryptographic secret key used for signing and verifying tokens.
/// - `token_expiration`: The duration (in seconds) for which an access token is valid.
/// - `refresh_token_expiration`: The duration (in seconds) for which a refresh token is valid.
#[derive(Debug, Clone, Default)]
pub struct AuthServiceVariables {
    /// The cryptographic secret key used for signing and verifying tokens.
    pub secret_key: String,

    /// The duration (in seconds) for which an access token is valid.
    pub token_expiration: u64,

    /// The duration (in seconds) for which a refresh token is valid.
    pub refresh_token_expiration: u64,
}

impl AuthServiceVariables {
    /// Creates a new instance of `AuthServiceVariables` with the specified parameters.
    ///
    /// # Arguments
    ///
    /// - `secret_key`: The cryptographic secret key used for signing and verifying tokens.
    /// - `token_expiration`: The duration (in seconds) for which an access token is valid.
    /// - `refresh_token_expiration`: The duration (in seconds) for which a refresh token is valid.
    pub fn new(secret_key: String, token_expiration: u64, refresh_token_expiration: u64) -> Self {
        Self {
            secret_key,
            token_expiration,
            refresh_token_expiration,
        }
    }
}
