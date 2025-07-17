#[derive(Debug, Clone, Default)]
pub struct AuthServiceVariables {
    pub secret_key: String,
    pub token_expiration: u64,
    pub refresh_token_expiration: u64,
}
