// src/utils.rs - Le Coffre à Outils Magique

//! Ce module contient des fonctions utilitaires générales utilisées à travers la crate.

/// Génère une chaîne aléatoire sécurisée pour les clés ou sels.
pub fn generate_random_string(length: usize) -> String {
    use rand::{rng, Rng};
    let chars: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    (0..length)
        .map(|_| {
            let idx = rng().random_range(0..chars.len());
            chars[idx] as char
        })
        .collect()
}
