#!/bin/bash
# scripts/setup-cargo.sh - Configurer Cargo.toml avec les dépendances et métadonnées

set -e

echo "⚙️ Configuration de Cargo.toml..."

CRATE_NAME="z3-auth"

# Sauvegarder Cargo.toml si il existe
if [[ -f "Cargo.toml" ]]; then
    cp Cargo.toml Cargo.toml.backup
fi

# Ajout des métadonnées après [lib] s'il existe
if grep -q "^\[lib\]" Cargo.toml; then
    sed -i "/^\[lib\]/a\\
description = \"Une crate d'authentification robuste et sécurisée pour Rust, inspirée par la sagesse protectrice d'Ahri.\"\\
license = \"MIT OR Apache-2.0\"\\
readme = \"README.md\"\\
repository = \"https://github.com/Zied-Yousfi/${CRATE_NAME}\"\\
keywords = [\"auth\", \"authentication\", \"security\", \"jwt\", \"argon2\", \"rust\", \"ahri\"]\\
categories = [\"authentication\", \"cryptography\", \"web-programming\"]\\
" Cargo.toml
fi

# Ajouter [dependencies] s'il n'existe pas
if ! grep -q "\[dependencies\]" Cargo.toml; then
    echo "" >> Cargo.toml
    echo "[dependencies]" >> Cargo.toml
fi

# Vérifier si les dépendances existent déjà
if grep -q "^argon2 =" Cargo.toml; then
    echo "  ⚠️  Dépendances déjà présentes, on évite les doublons..."
    exit 0
fi

# Ajouter les dépendances
cat >> Cargo.toml << 'EOF'

# Pour le hachage des mots de passe. Robuste et sécurisé.
argon2 = "0.5"
# Pour la manipulation des JWT.
jsonwebtoken = "9.0"
# Pour gérer les dates et durées (expiration des tokens).
chrono = { version = "0.4", features = ["serde"] }
# Pour générer des identifiants uniques.
uuid = { version = "1.0", features = ["serde", "v4"] }
# Pour tes types d'erreurs (ergonomie et clarté).
thiserror = "1.0"
# Pour la sérialisation/désérialisation (ex: config, claims JWT).
serde = { version = "1.0", features = ["derive"] }
# Pour rendre les méthodes de trait async.
async-trait = "0.1"
# Pour la génération de nombres aléatoires sécurisés (sels, etc.).
rand = "0.8"
# Pour la journalisation professionnelle (niveau infos/erreurs).
log = "0.4"

[dev-dependencies]
# Pour les tests asynchrones et les exemples
tokio = { version = "1", features = ["full"] }
# Pour la journalisation dans les tests/développement
env_logger = "0.10"
# Pour les benchmarks de performance
criterion = { version = "0.5", features = ["async", "async_tokio"], default-features = false }

[[bench]]
name = "hashing_perf"
harness = false
EOF

echo "  ✓ Cargo.toml configuré avec succès !"
