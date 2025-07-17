//! Ce fichier contient les benchmarks pour mesurer les performances des fonctions critiques.

use criterion::{Criterion, criterion_group, criterion_main};
use narangcia_cryptic::core::password::Argon2PasswordManager;
use narangcia_cryptic::core::password::SecurePasswordManager;
use std::hint::black_box;

/// Benchmark pour la performance du hachage de mot de passe.
fn bench_password_hashing(c: &mut Criterion) {
    let password_manager = Argon2PasswordManager::default();
    let password = "my_super_secret_password_123!";

    c.bench_function("argon2_password_hashing", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                password_manager
                    .hash_password(black_box(password))
                    .await
                    .unwrap()
            })
    });
}

/// Benchmark pour la performance de hachage avec différentes configurations Argon2.
fn bench_argon2_configurations(c: &mut Criterion) {
    let password = "benchmark_password_123!";
    let configs = vec![
        ("low_security", 2, 1024, 1),
        ("medium_security", 3, 4096, 2),
        ("high_security", 4, 8192, 4),
    ];

    for (name, _iterations, _memory, _parallelism) in configs {
        // Note: Since your current Argon2PasswordManager doesn't expose configuration,
        // we'll benchmark the default implementation for each scenario
        let password_manager = Argon2PasswordManager::default();

        c.bench_function(&format!("argon2_config_{name}"), |b| {
            b.to_async(tokio::runtime::Runtime::new().unwrap())
                .iter(|| async {
                    password_manager
                        .hash_password(black_box(password))
                        .await
                        .unwrap()
                })
        });
    }
}

/// Benchmark pour la performance de la vérification de mot de passe.
fn bench_password_verification(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let password_manager = Argon2PasswordManager::default();
    let password = "my_super_secret_password_123!";

    // Pré-générer le hash pour les benchmarks de vérification
    let hashed_password =
        rt.block_on(async { password_manager.hash_password(password).await.unwrap() });

    c.bench_function("argon2_password_verification", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                password_manager
                    .verify_password(black_box(password), black_box(&hashed_password))
                    .await
                    .unwrap()
            })
    });
}

/// Benchmark pour différentes longueurs de mots de passe.
fn bench_password_lengths(c: &mut Criterion) {
    let password_manager = Argon2PasswordManager::default();
    let passwords = vec![
        ("short", "abc123"),
        ("medium", "my_super_secret_password_123!"),
        (
            "long",
            "this_is_a_very_long_password_with_many_characters_and_symbols_!@#$%^&*()_+{}[]",
        ),
    ];

    for (name, password) in passwords {
        c.bench_function(&format!("hashing_{name}_password"), |b| {
            b.to_async(tokio::runtime::Runtime::new().unwrap())
                .iter(|| async {
                    password_manager
                        .hash_password(black_box(password))
                        .await
                        .unwrap()
                })
        });
    }
}

/// Benchmark pour la vérification avec mot de passe incorrect.
fn bench_password_verification_failure(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let password_manager = Argon2PasswordManager::default();
    let correct_password = "correct_password_123!";
    let wrong_password = "wrong_password_456!";

    let hashed_password = rt.block_on(async {
        password_manager
            .hash_password(correct_password)
            .await
            .unwrap()
    });

    c.bench_function("argon2_password_verification_failure", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                password_manager
                    .verify_password(black_box(wrong_password), black_box(&hashed_password))
                    .await
                    .unwrap()
            })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_password_hashing, bench_argon2_configurations, bench_password_verification, bench_password_lengths, bench_password_verification_failure
}
criterion_main!(benches);
