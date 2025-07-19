use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use narangcia_cryptic::{
    AuthService,
    core::{
        credentials::{Credentials, PlainPassword},
        hash::{Argon2Hasher, generate_secure_salt},
        password::Argon2PasswordManager,
        token::{TokenService, jwt::JwtTokenService},
        user::{
            User,
            persistence::{InMemoryUserRepo, UserRepository},
        },
    },
};
use std::{hint::black_box, sync::Arc};
use tokio::runtime::Runtime;

// --- Hash and Salt Benchmarks ---
fn bench_generate_secure_salt(c: &mut Criterion) {
    c.bench_function("generate_secure_salt", |b| {
        b.iter(|| {
            let salt = generate_secure_salt();
            black_box(salt)
        })
    });
}

fn bench_argon2_hash(c: &mut Criterion) {
    let hasher = Argon2Hasher::new();
    let password = b"benchmark_password_12345";
    let salt = generate_secure_salt().unwrap();

    c.bench_function("argon2_hash", |b| {
        b.iter(|| {
            let hash = hasher.hash(black_box(password), Some(&salt));
            black_box(hash)
        })
    });
}

fn bench_argon2_verify(c: &mut Criterion) {
    let hasher = Argon2Hasher::new();
    let password = b"benchmark_password_12345";
    let salt = generate_secure_salt().unwrap();
    let hash = hasher.hash(password, Some(&salt)).unwrap();

    c.bench_function("argon2_verify", |b| {
        b.iter(|| {
            let result = hasher.verify(black_box(password), black_box(&hash));
            black_box(result)
        })
    });
}

// --- JWT Token Benchmarks ---
fn bench_jwt_generate_token_pair(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let jwt_service = JwtTokenService::new("benchmark_secret_key_1234567890", 3600, 7200);
    let user_id = "benchmark_user_123";

    c.bench_function("jwt_generate_token_pair", |b| {
        b.to_async(&rt).iter(|| async {
            let result = jwt_service.generate_token_pair(black_box(user_id)).await;
            black_box(result)
        })
    });
}

fn bench_jwt_validate_access_token(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let jwt_service = JwtTokenService::new("benchmark_secret_key_1234567890", 3600, 7200);
    let user_id = "benchmark_user_123";

    let token_pair = rt.block_on(async { jwt_service.generate_token_pair(user_id).await.unwrap() });

    c.bench_function("jwt_validate_access_token", |b| {
        b.to_async(&rt).iter(|| async {
            let result = jwt_service
                .validate_access_token(black_box(&token_pair.access_token))
                .await;
            black_box(result)
        })
    });
}

fn bench_jwt_refresh_access_token(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let jwt_service = JwtTokenService::new("benchmark_secret_key_1234567890", 3600, 7200);
    let user_id = "benchmark_user_123";

    let token_pair = rt.block_on(async { jwt_service.generate_token_pair(user_id).await.unwrap() });

    c.bench_function("jwt_refresh_access_token", |b| {
        b.to_async(&rt).iter(|| async {
            let result = jwt_service
                .refresh_access_token(black_box(&token_pair.refresh_token))
                .await;
            black_box(result)
        })
    });
}

// --- User Creation and Management Benchmarks ---
fn bench_user_creation_with_plain_password(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let password_manager = Arc::new(Argon2PasswordManager::default());

    c.bench_function("user_creation_with_plain_password", |b| {
        b.to_async(&rt).iter(|| async {
            let user = User::with_plain_password(
                password_manager.as_ref(),
                black_box("bench_user_id".to_string()),
                black_box("bench_username".to_string()),
                black_box(PlainPassword::new("bench_password".to_string())),
            )
            .await;
            black_box(user)
        })
    });
}

// --- In-Memory Repository Benchmarks ---
fn bench_in_memory_repo_add_user(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let password_manager = Arc::new(Argon2PasswordManager::default());

    // Pre-create users for benchmarking
    let users: Vec<User> = rt.block_on(async {
        let mut users = Vec::new();
        for i in 0..100 {
            let user = User::with_plain_password(
                password_manager.as_ref(),
                format!("bench_user_{i}"),
                format!("bench_username_{i}"),
                PlainPassword::new(format!("bench_password_{i}")),
            )
            .await
            .unwrap();
            users.push(user);
        }
        users
    });

    let mut group = c.benchmark_group("in_memory_repo");

    group.bench_function("add_user", |b| {
        b.to_async(&rt).iter(|| {
            let users = users.clone();
            async move {
                let repo = InMemoryUserRepo::new();
                let user = users[0].clone(); // Use first user instead of counter
                let result = repo.add_user(black_box(user)).await;
                black_box(result)
            }
        })
    });

    group.finish();
}

fn bench_in_memory_repo_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let password_manager = Arc::new(Argon2PasswordManager::default());

    // Setup repo with pre-populated data
    let (repo, users) = rt.block_on(async {
        let repo = InMemoryUserRepo::new();
        let mut users = Vec::new();

        for i in 0..1000 {
            let user = User::with_plain_password(
                password_manager.as_ref(),
                format!("bench_user_{i}"),
                format!("bench_username_{i}"),
                PlainPassword::new(format!("bench_password_{i}")),
            )
            .await
            .unwrap();

            repo.add_user(user.clone()).await.unwrap();
            users.push(user);
        }

        (repo, users)
    });

    let mut group = c.benchmark_group("in_memory_repo_operations");

    group.bench_function("get_user_by_id", |b| {
        b.to_async(&rt).iter(|| async {
            let user_id = format!("bench_user_{}", black_box(500));
            let result = repo.get_user_by_id(&user_id).await;
            black_box(result)
        })
    });

    group.bench_function("get_user_by_identifier", |b| {
        b.to_async(&rt).iter(|| async {
            let identifier = format!("bench_username_{}", black_box(500));
            let result = repo.get_user_by_identifier(&identifier).await;
            black_box(result)
        })
    });

    group.bench_function("update_user", |b| {
        b.to_async(&rt).iter(|| async {
            let mut user = users[500].clone();
            user.credentials.identifier = format!("updated_username_{}", black_box(500));
            let result = repo.update_user(black_box(user)).await;
            black_box(result)
        })
    });

    group.finish();
}

// --- AuthService Benchmarks ---
fn bench_auth_service_signup(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("auth_service_signup", |b| {
        b.to_async(&rt).iter(|| async move {
            let auth_service = AuthService::default();
            let uuid = uuid::Uuid::new_v4().to_string();
            let user = User::with_plain_password(
                auth_service.password_manager.as_ref(),
                format!("bench_signup_user_{uuid}"),
                format!("bench_signup_username_{uuid}"),
                PlainPassword::new(format!("bench_signup_password_{uuid}")),
            )
            .await
            .unwrap();

            let result = auth_service.signup(black_box(user)).await;
            black_box(result)
        })
    });
}

fn bench_auth_service_login(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let auth_service = AuthService::default();

    // Pre-populate with a user for login benchmarks
    rt.block_on(async {
        let user = User::with_plain_password(
            auth_service.password_manager.as_ref(),
            "bench_login_user_id".to_string(),
            "bench_login_user".to_string(),
            PlainPassword::new("bench_login_password".to_string()),
        )
        .await
        .unwrap();

        auth_service.signup(user).await.unwrap();
    });

    c.bench_function("auth_service_login_success", |b| {
        b.to_async(&rt).iter(|| async {
            let result = auth_service
                .login_with_credentials(
                    black_box("bench_login_user"),
                    black_box("bench_login_password"),
                )
                .await;
            black_box(result)
        })
    });

    c.bench_function("auth_service_login_failure", |b| {
        b.to_async(&rt).iter(|| async {
            let result = auth_service
                .login_with_credentials(black_box("nonexistent_user"), black_box("wrong_password"))
                .await;
            black_box(result)
        })
    });
}

// --- Credentials Benchmarks ---
fn bench_credentials_creation_and_verification(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let manager = Argon2PasswordManager::default();
    let identifier = "bench_user".to_string();
    let password = "bench_password".to_string();

    let mut group = c.benchmark_group("credentials");

    group.bench_function("create_from_plain_password", |b| {
        b.to_async(&rt).iter(|| async {
            let plain = PlainPassword::new(black_box(password.clone()));
            let result = Credentials::from_plain_password(
                &manager,
                black_box(identifier.clone()),
                black_box(identifier.clone()),
                black_box(plain),
            )
            .await;
            black_box(result)
        })
    });

    // Pre-create credentials for verification benchmark
    let credentials = rt.block_on(async {
        let plain = PlainPassword::new(password.clone());
        Credentials::from_plain_password(&manager, identifier.clone(), identifier.clone(), plain)
            .await
            .unwrap()
    });

    group.bench_function("verify_password_success", |b| {
        b.to_async(&rt).iter(|| async {
            let plain = PlainPassword::new(black_box(password.clone()));
            let result = credentials.verify_password(&manager, &plain).await;
            black_box(result)
        })
    });

    group.bench_function("verify_password_failure", |b| {
        b.to_async(&rt).iter(|| async {
            let plain = PlainPassword::new(black_box("wrong_password".to_string()));
            let result = credentials.verify_password(&manager, &plain).await;
            black_box(result)
        })
    });

    group.finish();
}

// --- Scaling Benchmarks ---
fn bench_jwt_scaling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("jwt_scaling");

    for token_count in [1, 10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::new("generate_multiple_tokens", token_count),
            token_count,
            |b, &token_count| {
                b.to_async(&rt).iter(|| async {
                    let jwt_service = JwtTokenService::new("scaling_secret", 3600, 7200);
                    let mut tokens = Vec::new();

                    for i in 0..token_count {
                        let user_id = format!("scaling_user_{i}");
                        let token_pair = jwt_service.generate_token_pair(&user_id).await.unwrap();
                        tokens.push(token_pair);
                    }

                    black_box(tokens)
                })
            },
        );
    }

    group.finish();
}

fn bench_repo_scaling(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let password_manager = Arc::new(Argon2PasswordManager::default());

    let mut group = c.benchmark_group("repo_scaling");

    for user_count in [10, 100, 1000, 10000].iter() {
        group.bench_with_input(
            BenchmarkId::new("populate_repo", user_count),
            user_count,
            |b, &user_count| {
                b.to_async(&rt).iter(|| async {
                    let repo = InMemoryUserRepo::new();

                    for i in 0..user_count {
                        let user = User::with_plain_password(
                            password_manager.as_ref(),
                            format!("scaling_user_{i}"),
                            format!("scaling_username_{i}"),
                            PlainPassword::new(format!("scaling_password_{i}")),
                        )
                        .await
                        .unwrap();

                        repo.add_user(user).await.unwrap();
                    }

                    black_box(repo)
                })
            },
        );
    }

    group.finish();
}

// Group all benchmarks
criterion_group!(
    hash_benches,
    bench_generate_secure_salt,
    bench_argon2_hash,
    bench_argon2_verify
);

criterion_group!(
    jwt_benches,
    bench_jwt_generate_token_pair,
    bench_jwt_validate_access_token,
    bench_jwt_refresh_access_token
);

criterion_group!(user_benches, bench_user_creation_with_plain_password);

criterion_group!(
    repo_benches,
    bench_in_memory_repo_add_user,
    bench_in_memory_repo_operations
);

criterion_group!(
    auth_service_benches,
    bench_auth_service_signup,
    bench_auth_service_login
);

criterion_group!(
    credentials_benches,
    bench_credentials_creation_and_verification
);

criterion_group!(scaling_benches, bench_jwt_scaling, bench_repo_scaling);

// Main entry point
criterion_main!(
    hash_benches,
    jwt_benches,
    user_benches,
    repo_benches,
    auth_service_benches,
    credentials_benches,
    scaling_benches
);
