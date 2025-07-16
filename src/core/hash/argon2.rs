use argon2::{
    Argon2,
    password_hash::{
        Error as PasswordHashError, PasswordHash, PasswordHasher, PasswordVerifier, SaltString,
    },
};

#[derive(Default)]
pub struct Argon2Hasher {
    hasher: Argon2<'static>,
}

impl Argon2Hasher {
    pub fn new() -> Self {
        Self {
            hasher: Argon2::default(),
        }
    }

    /// Hash arbitrary data with a provided salt (or generate one if None)
    pub fn hash(
        &self,
        data: &[u8],
        salt: Option<&SaltString>,
    ) -> Result<String, PasswordHashError> {
        let salt = match salt {
            Some(s) => s.clone(),
            None => crate::core::hash::salt::generate_secure_salt()?,
        };
        let hash = self.hasher.hash_password(data, &salt)?;
        Ok(hash.to_string())
    }

    /// Verify arbitrary data against a hash string
    pub fn verify(&self, data: &[u8], hash_str: &str) -> Result<bool, PasswordHashError> {
        let parsed_hash = PasswordHash::new(hash_str)?;
        match self.hasher.verify_password(data, &parsed_hash) {
            Ok(()) => Ok(true),
            Err(PasswordHashError::Password) => Ok(false),
            Err(e) => Err(e),
        }
    }
}
