use argon2::password_hash::{Error as PasswordHashError, SaltString};
use rand::{TryRngCore, rngs::OsRng};

pub fn generate_secure_salt() -> Result<SaltString, PasswordHashError> {
    let mut bytes = [0u8; 16]; // 16 bytes is a common salt length

    // Gestion d'erreur explicite pour la génération aléatoire
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| PasswordHashError::Password)?;

    // Création du SaltString avec gestion d'erreur
    SaltString::encode_b64(&bytes)
}
