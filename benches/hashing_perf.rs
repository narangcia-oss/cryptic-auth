// benches/hashing_perf.rs - Les Mesures de Vitesse des Sortilèges

//! Ce fichier contient les benchmarks pour mesurer les performances des fonctions critiques.

use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

// Fonction mock simple pour simuler un travail async
async fn mock_hashing(password: &str) -> String {
    // Simule une opération de hachage CPU-intensive
    for _i in 0..1_000_000 {
        let _ = password.chars().next();
    }
    format!("mock_hashed_{password}")
}

/// Benchmark pour la performance du hachage de mot de passe.
fn bench_password_hashing(c: &mut Criterion) {
    let password = "my_super_secret_password_123!";
    c.bench_function("password_hashing", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { mock_hashing(black_box(password)).await })
    });
}

async fn mock_verification(password: &str, hashed_password: &str) -> bool {
    for _i in 0..500_000 {
        let _ = password.chars().next();
    }
    format!("mock_hashed_{password}") == hashed_password
}

/// Benchmark pour la performance de la vérification de mot de passe.
fn bench_password_verification(c: &mut Criterion) {
    let password = "my_super_secret_password_123!";
    let hashed_password = "mock_hashed_my_super_secret_password_123!";
    c.bench_function("password_verification", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async {
                mock_verification(black_box(password), black_box(hashed_password)).await
            })
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench_password_hashing, bench_password_verification
}
criterion_main!(benches);
