use crate::core::token::claims::{AccessTokenClaims, Claims, RefreshTokenClaims};
use crate::core::token::{TokenPair, TokenService};
use crate::error::AuthError;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use std::time::{SystemTime, UNIX_EPOCH};

/// JWT Token Service implementation
pub struct JwtTokenService {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    algorithm: Algorithm,
    access_token_duration: u64,  // in seconds
    refresh_token_duration: u64, // in seconds
}

impl JwtTokenService {
    /// Creates a new JWT service with a secret key
    pub fn new(secret: &str, access_token_duration: u64, refresh_token_duration: u64) -> Self {
        let key_bytes = secret.as_bytes();

        Self {
            encoding_key: EncodingKey::from_secret(key_bytes),
            decoding_key: DecodingKey::from_secret(key_bytes),
            algorithm: Algorithm::HS256,
            access_token_duration,
            refresh_token_duration,
        }
    }

    /// Gets the current timestamp
    fn current_timestamp() -> Result<usize, AuthError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthError::TokenGeneration("Failed to get current time".to_string()))
            .map(|duration| duration.as_secs() as usize)
    }

    /// Generates an access token
    fn generate_access_token(&self, user_id: &str) -> Result<String, AuthError> {
        let now = Self::current_timestamp()?;
        let expiration = now + self.access_token_duration as usize;

        let claims = AccessTokenClaims {
            sub: user_id.to_string(),
            exp: expiration,
            iat: now,
            token_type: "access".to_string(),
        };

        let header = Header::new(self.algorithm);

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AuthError::TokenGeneration(format!("Failed to encode access token: {e}")))
    }

    /// Generates a refresh token
    fn generate_refresh_token(&self, user_id: &str) -> Result<String, AuthError> {
        let now = Self::current_timestamp()?;
        let expiration = now + self.refresh_token_duration as usize;

        let claims = RefreshTokenClaims {
            sub: user_id.to_string(),
            exp: expiration,
            iat: now,
            token_type: "refresh".to_string(),
        };

        let header = Header::new(self.algorithm);

        encode(&header, &claims, &self.encoding_key)
            .map_err(|e| AuthError::TokenGeneration(format!("Failed to encode refresh token: {e}")))
    }

    /// Validates a generic token
    fn validate_token<T>(&self, token: &str) -> Result<T, AuthError>
    where
        T: serde::de::DeserializeOwned,
    {
        let validation = Validation::new(self.algorithm);

        decode::<T>(token, &self.decoding_key, &validation)
            .map(|token_data| token_data.claims)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::TokenExpired,
                jsonwebtoken::errors::ErrorKind::InvalidToken => {
                    AuthError::InvalidToken("Invalid token format".to_string())
                }
                jsonwebtoken::errors::ErrorKind::InvalidSignature => {
                    AuthError::InvalidToken("Invalid token signature".to_string())
                }
                _ => AuthError::TokenValidation(format!("Token validation failed: {e}")),
            })
    }
}

#[async_trait::async_trait]
impl TokenService for JwtTokenService {
    /// Generates a token pair
    async fn generate_token_pair(&self, user_id: &str) -> Result<TokenPair, AuthError> {
        let access_token = self.generate_access_token(user_id)?;
        let refresh_token = self.generate_refresh_token(user_id)?;

        Ok(TokenPair {
            access_token,
            refresh_token,
        })
    }

    /// Validates an access token
    async fn validate_access_token(
        &self,
        token: &str,
    ) -> Result<Box<dyn Claims + Send + Sync>, AuthError> {
        let claims: AccessTokenClaims = self.validate_token(token)?;
        Ok(Box::new(claims))
    }

    /// Refreshes an access token
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<TokenPair, AuthError> {
        let refresh_claims: RefreshTokenClaims = self.validate_token(refresh_token)?;

        if refresh_claims.token_type != "refresh" {
            return Err(AuthError::InvalidToken(
                "Expected refresh token".to_string(),
            ));
        }

        self.generate_token_pair(&refresh_claims.sub).await
    }
}
