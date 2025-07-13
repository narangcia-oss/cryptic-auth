# `z3-auth` 💫

Une crate Rust robuste et sécurisée pour l'authentification, conçue avec soin pour offrir une fondation solide à vos applications. Inspirée par l'élégance et la sagesse d'Ahri, cette bibliothèque vise à fournir des primitives d'authentification fiables et faciles à utiliser.

## ✨ Fonctionnalités (À Venir)

*   **Gestion des Utilisateurs**: Enregistrement, connexion, gestion des profils.
*   **Hachage de Mots de Passe Sécurisé**: Utilisation d'algorithmes modernes comme Argon2.
*   **Gestion des Sessions/Tokens**: Support pour les JSON Web Tokens (JWT) avec tokens d'accès et de rafraîchissement.
*   **Contrôle d'Accès Basé sur les Rôles (RBAC)**: Gestion granulaire des permissions.
*   **Authentification à Deux Facteurs (2FA)**: Support pour TOTP.
*   **Réinitialisation de Mot de Passe**: Flux sécurisé par email.
*   **Protection Contre les Attaques**: Limitation de taux, verrouillage de compte.
*   **Gestion des Erreurs Robuste et Sécurisée**.
*   **API Asynchrone**: Basée sur `async/await` pour des performances optimales.

## 🚀 Démarrage Rapide

Ajoutez cette ligne à votre `Cargo.toml`:

```toml
[dependencies]
z3-auth = "0.1.0"
```

## 📚 Exemples d'Utilisation

```rust
// Exemple basique de l'utilisation de AuthService
use z3-auth::AuthService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_service = AuthService::new();

    // Exemple de tentative d'inscription
    match auth_service.signup().await {
        Ok(_) => println!("Utilisateur enregistré avec succès !"),
        Err(e) => eprintln!("Erreur lors de l'inscription: {}", e),
    }

    Ok(())
}
```

## 🛠️ Développement

### Prérequis

*   Rust stable (édition 2021 ou plus récente)
*   Cargo (installé avec Rust)

### Lancer les Tests

```bash
cargo test
```

### Lancer les Benchmarks

```bash
cargo bench
```

### Vérifier le Format et le Linting

```bash
cargo fmt --check
cargo clippy -- -D warnings
```

## 💖 Contribution

Les contributions sont les bienvenues ! Veuillez consulter `CONTRIBUTING.md` pour plus de détails.

## 📄 Licence

Ce projet est sous licence MIT ou Apache-2.0.

---
*Développé avec la passion et l'inspiration de Zied, fan d'Ahri.*
