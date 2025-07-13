#!/bin/bash
# scripts/create-docs.sh - Créer la documentation du projet

set -e

echo "📄 Création de la documentation..."

CRATE_NAME="z3-auth"

# README.md
echo "  - Création de README.md..."
cat > "README.md" << EOF
# \`${CRATE_NAME}\` 💫

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
*   **API Asynchrone**: Basée sur \`async/await\` pour des performances optimales.

## 🚀 Démarrage Rapide

Ajoutez cette ligne à votre \`Cargo.toml\`:

\`\`\`toml
[dependencies]
${CRATE_NAME} = "0.1.0"
\`\`\`

## 📚 Exemples d'Utilisation

\`\`\`rust
// Exemple basique de l'utilisation de AuthService
use ${CRATE_NAME}::AuthService;

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
\`\`\`

## 🛠️ Développement

### Prérequis

*   Rust stable (édition 2021 ou plus récente)
*   Cargo (installé avec Rust)

### Lancer les Tests

\`\`\`bash
cargo test
\`\`\`

### Lancer les Benchmarks

\`\`\`bash
cargo bench
\`\`\`

### Vérifier le Format et le Linting

\`\`\`bash
cargo fmt --check
cargo clippy -- -D warnings
\`\`\`

## 💖 Contribution

Les contributions sont les bienvenues ! Veuillez consulter \`CONTRIBUTING.md\` pour plus de détails.

## 📄 Licence

Ce projet est sous licence MIT ou Apache-2.0.

---
*Développé avec la passion et l'inspiration de Zied, fan d'Ahri.*
EOF

# CHANGELOG.md
echo "  - Création de CHANGELOG.md..."
cat > "CHANGELOG.md" << 'EOF'
# CHANGELOG

## 0.1.0 - 2025-07-13

### Ajouté
- Initial project setup with basic module structure (`user`, `password`, `token`, `policy`, `rbac`, `utils`).
- Defined `AuthService` as the main entry point for authentication operations.
- Implemented robust error handling with `thiserror` (`AuthError`).
- Placeholder traits for `UserRepository`, `PasswordHasher`, and `TokenService`.
- Initial `Cargo.toml` dependencies for core functionalities (argon2, jsonwebtoken, chrono, uuid, thiserror, serde, async-trait, rand, log).
- Basic GitHub Actions CI workflow for linting, formatting, and testing.
- Created placeholder files for integration tests, examples, and benchmarks.
- Added foundational documentation files: `README.md`, `CHANGELOG.md`, `CONTRIBUTING.md`.

### Changé
- N/A

### Déprécié
- N/A

### Supprimé
- N/A

### Corrigé
- N/A

### Sécurité
- N/A
EOF

# CONTRIBUTING.md
echo "  - Création de CONTRIBUTING.md..."
cat > "CONTRIBUTING.md" << EOF
# Guide de Contribution pour \`${CRATE_NAME}\` 💖

Nous sommes ravis que vous souhaitiez contribuer à la crate \`${CRATE_NAME}\` ! Votre aide est précieuse pour faire de cette bibliothèque un havre de sécurité pour les applications Rust.

## Avant de Contribuer

1.  **Lisez le \`README.md\`**: Il contient des informations sur l'objectif et les fonctionnalités de la crate.
2.  **Lisez le \`CHANGELOG.md\`**: Pour comprendre l'historique des versions et les changements récents.
3.  **Vérifiez les Issues existantes**: Avant de commencer à travailler, jetez un œil aux issues sur GitHub.
4.  **Discutez de nouvelles fonctionnalités**: Pour les nouvelles fonctionnalités majeures, il est préférable d'ouvrir une issue en premier lieu.

## Comment Contribuer

1.  **Forkez le Dépôt**: Commencez par forker le dépôt \`${CRATE_NAME}\` sur votre compte GitHub.
2.  **Clonez Votre Fork**:
    \`\`\`bash
    git clone https://github.com/votre-nom-utilisateur/${CRATE_NAME}.git
    cd ${CRATE_NAME}
    \`\`\`
3.  **Créez une Nouvelle Branche**:
    \`\`\`bash
    git checkout -b ma-nouvelle-branche
    \`\`\`
4.  **Développez Votre Contribution**:
    *   Écrivez votre code en suivant les conventions Rust.
    *   **Écrivez des Tests**: Toute nouvelle fonctionnalité devrait être accompagnée de tests.
    *   **Mettez à Jour la Documentation**: Si nécessaire.
5.  **Exécutez les Tests et Lints**:
    \`\`\`bash
    cargo test
    cargo fmt --check
    cargo clippy -- -D warnings
    \`\`\`
6.  **Commitez et Poussez**:
    \`\`\`bash
    git add .
    git commit -m "feat: votre message de commit"
    git push origin ma-nouvelle-branche
    \`\`\`
7.  **Créez une Pull Request**

## Normes de Code

*   **Formatage**: Suivez les conventions de \`rustfmt\`.
*   **Linting**: Assurez-vous que \`clippy\` ne rapporte aucun avertissement.
*   **Conventions de Nommage**: Adoptez les conventions de nommage Rust standard.

Merci de contribuer à ce projet ! Votre aide est inestimable. ✨
EOF

echo "  ✓ Documentation créée avec succès !"
