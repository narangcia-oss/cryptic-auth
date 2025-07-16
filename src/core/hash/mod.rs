pub mod argon2;
pub mod salt;

pub use argon2::Argon2Hasher;

pub use salt::generate_secure_salt;
