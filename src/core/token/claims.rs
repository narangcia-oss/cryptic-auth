//! Defines the claims structures for authentication tokens.

use serde::{Deserialize, Serialize};

/// Trait pour tous les types de claims
pub trait Claims {
    fn get_subject(&self) -> &str;
    fn get_expiration(&self) -> usize;
}

/// Claims pour les access tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub sub: String,        // user_id
    pub exp: usize,         // expiration timestamp
    pub iat: usize,         // issued at timestamp
    pub token_type: String, // "access"
}

impl Claims for AccessTokenClaims {
    fn get_subject(&self) -> &str {
        &self.sub
    }

    fn get_expiration(&self) -> usize {
        self.exp
    }
}

/// Claims pour les refresh tokens
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    pub sub: String,        // user_id
    pub exp: usize,         // expiration timestamp
    pub iat: usize,         // issued at timestamp
    pub token_type: String, // "refresh"
}

impl Claims for RefreshTokenClaims {
    fn get_subject(&self) -> &str {
        &self.sub
    }

    fn get_expiration(&self) -> usize {
        self.exp
    }
}
