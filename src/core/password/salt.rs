use argon2::password_hash::{Error as PasswordHashError, SaltString};
use rand::{TryRngCore, rngs::OsRng};

pub fn generate_secure_salt() -> Result<SaltString, PasswordHashError> {
    let mut bytes = [0u8; 16];

    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PasswordHashError::Password)?;

    SaltString::encode_b64(&bytes)
}
