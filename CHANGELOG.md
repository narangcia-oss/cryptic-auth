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
