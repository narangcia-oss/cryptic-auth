//! Claims structures for authentication tokens.
//!
//! This module defines the data structures and traits used for representing the claims
//! embedded in authentication tokens, such as access and refresh tokens. These claims
//! are used to securely encode information about the user and token validity, and are
//! typically serialized/deserialized as part of JWTs (JSON Web Tokens).

use serde::{Deserialize, Serialize};

/// Trait for all types of claims used in authentication tokens.
///
/// This trait provides a common interface for extracting the subject (typically the user ID)
/// and expiration timestamp from any claim structure.
pub trait Claims {
    /// Returns the subject of the claim (usually the user identifier).
    fn get_subject(&self) -> &str;
    /// Returns the expiration timestamp (as a UNIX timestamp in seconds).
    fn get_expiration(&self) -> usize;
}

/// Claims for access tokens.
///
/// Access tokens are short-lived tokens used to authenticate requests to protected resources.
/// This struct contains the standard fields required for access token validation and identification.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// Subject (user ID) to whom the token was issued.
    pub sub: String,
    /// Expiration timestamp (UNIX timestamp, seconds).
    pub exp: usize,
    /// Issued at timestamp (UNIX timestamp, seconds).
    pub iat: usize,
    /// Type of the token (should be "access").
    pub token_type: String,
}

impl Claims for AccessTokenClaims {
    /// Returns the subject (user ID) of the access token.
    fn get_subject(&self) -> &str {
        &self.sub
    }

    /// Returns the expiration timestamp of the access token.
    fn get_expiration(&self) -> usize {
        self.exp
    }
}

/// Claims for refresh tokens.
///
/// Refresh tokens are long-lived tokens used to obtain new access tokens after the original
/// access token expires. This struct contains the standard fields required for refresh token
/// validation and identification.
#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshTokenClaims {
    /// Subject (user ID) to whom the token was issued.
    pub sub: String,
    /// Expiration timestamp (UNIX timestamp, seconds).
    pub exp: usize,
    /// Issued at timestamp (UNIX timestamp, seconds).
    pub iat: usize,
    /// Type of the token (should be "refresh").
    pub token_type: String,
}

impl Claims for RefreshTokenClaims {
    /// Returns the subject (user ID) of the refresh token.
    fn get_subject(&self) -> &str {
        &self.sub
    }

    /// Returns the expiration timestamp of the refresh token.
    fn get_expiration(&self) -> usize {
        self.exp
    }
}
