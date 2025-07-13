#!/bin/bash
# scripts/create-tests.sh - Créer les tests et exemples

set -e

echo "✨ Création des tests et exemples..."

TESTS_DIR="tests"
EXAMPLES_DIR="examples"
BENCHES_DIR="benches"
CRATE_NAME="z3-auth"

# Tests d'intégration
echo "  - Création des tests d'intégration..."
cat > "$TESTS_DIR/integration_test.rs" << EOF
// tests/integration_test.rs - Les Rituels de Vérification Intégrés

//! Ce fichier contient les tests d'intégration pour la crate 'z3-auth'.

use z3_auth::AuthService;

#[tokio::test]
async fn test_auth_service_signup_not_implemented() {
    let auth_service = AuthService::new();

    let result = auth_service.signup().await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Feature not implemented yet: signup"
    );
}

#[tokio::test]
async fn test_auth_service_login_not_implemented() {
    let auth_service = AuthService::new();

    let result = auth_service.login().await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Feature not implemented yet: login"
    );
}
EOF

# Exemples
echo "  - Création des exemples..."
cat > "$EXAMPLES_DIR/basic_usage.rs" << EOF
// examples/basic_usage.rs - Lumière sur l'Utilisation de la Crate

//! Cet exemple démontre une utilisation basique de la crate 'z3-auth'.

use z3_auth::AuthService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌟 Démarrage de l'exemple basique de ${CRATE_NAME}...");

    let auth_service = AuthService::new();

    println!("Tentative de processus d'inscription...");
    match auth_service.signup().await {
        Ok(_) => println!("🎉 Inscription simulée réussie !"),
        Err(e) => eprintln!("❌ Erreur simulée lors de l'inscription: {}", e),
    }

    println!("\nTentative de processus de connexion...");
    match auth_service.login().await {
        Ok(_) => println!("✨ Connexion simulée réussie !"),
        Err(e) => eprintln!("❌ Erreur simulée lors de la connexion: {}", e),
    }

    println!("\nC'est la fin de cet exemple. Continuez à construire votre magie ! ✨");
    Ok(())
}
EOF

# Benchmarks
echo "  - Création des benchmarks..."
cat > "$BENCHES_DIR/hashing_perf.rs" << 'EOF'
// benches/hashing_perf.rs - Les Mesures de Vitesse des Sortilèges

//! Ce fichier contient les benchmarks pour mesurer les performances des fonctions critiques.

use criterion::{black_box, criterion_group, criterion_main, Criterion};

// Fonction mock simple pour simuler un travail async
async fn mock_hashing(password: &str) -> String {
    // Simule une opération de hachage CPU-intensive
    for _i in 0..1_000_000 {
        let _ = password.chars().next();
    }
    format!("mock_hashed_{}", password)
}

/// Benchmark pour la performance du hachage de mot de passe.
fn bench_password_hashing(c: &mut Criterion) {
    let password = "my_super_secret_password_123!";
    c.bench_function("password_hashing", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap()).iter(|| async {
            mock_hashing(black_box(password)).await
        })
    });
}

async fn mock_verification(password: &str, hashed_password: &str) -> bool {
    for _i in 0..500_000 {
        let _ = password.chars().next();
    }
    format!("mock_hashed_{}", password) == hashed_password
}

/// Benchmark pour la performance de la vérification de mot de passe.
fn bench_password_verification(c: &mut Criterion) {
    let password = "my_super_secret_password_123!";
    let hashed_password = "mock_hashed_my_super_secret_password_123!";
    c.bench_function("password_verification", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap()).iter(|| async {
            mock_verification(black_box(password), black_box(&hashed_password)).await
        })
    });
}

criterion_group!{
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_password_hashing, bench_password_verification
}
criterion_main!(benches);
EOF

echo "  ✓ Tests et exemples créés avec succès !"
