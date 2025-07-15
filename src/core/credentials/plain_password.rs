//! This module defines the PlainPassword structure for secure handling
//! of plaintext passwords with automatic memory clearing.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Temporary structure for plaintext passwords
/// Automatically clears itself from memory
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct PlainPassword(String);

impl PlainPassword {
    pub fn new(password: String) -> Self {
        Self(password)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}
