//! Defines the claims structures for authentication tokens.

use chrono::{TimeZone, Utc, serde::ts_seconds};
use serde::{Deserialize, Serialize};

/// Common trait for all token claims.
pub trait Claims {
    fn expiration(&self) -> i64;
    fn set_expiration(&mut self, exp: i64);
    fn issued_at(&self) -> i64;
    fn set_issued_at(&mut self, iat: i64);
}

/// Default claims for a JWT access token.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessClaims {
    pub sub: String, // Subject (user ID)
    #[serde(with = "ts_seconds")]
    pub exp: chrono::DateTime<Utc>, // Expiration timestamp
    #[serde(with = "ts_seconds")]
    pub iat: chrono::DateTime<Utc>, // Issued at timestamp
    pub aud: Option<String>, // Audience
    pub iss: Option<String>, // Issuer
}

impl Claims for AccessClaims {
    fn expiration(&self) -> i64 {
        self.exp.timestamp()
    }
    fn set_expiration(&mut self, exp: i64) {
        self.exp = Utc.timestamp_opt(exp, 0).unwrap();
    }
    fn issued_at(&self) -> i64 {
        self.iat.timestamp()
    }
    fn set_issued_at(&mut self, iat: i64) {
        self.iat = Utc.timestamp_opt(iat, 0).unwrap();
    }
}
