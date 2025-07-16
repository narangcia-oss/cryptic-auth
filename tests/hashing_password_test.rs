use z3_auth::core::password::Argon2PasswordManager;
use z3_auth::core::password::SecurePasswordManager;

#[tokio::test]
async fn test_password_hashing_and_verification() {
    let manager = Argon2PasswordManager::new();
    let password = "mon_super_mot_de_passe_sécurisé";

    // Test du hachage
    let hashed = manager.hash_password(password).await.unwrap();
    assert!(!hashed.is_empty());
    assert_ne!(hashed, password);

    // Test de la vérification (mot de passe correct)
    let is_valid = manager.verify_password(password, &hashed).await.unwrap();
    assert!(is_valid);

    // Test de la vérification (mot de passe incorrect)
    let is_invalid = manager
        .verify_password("mauvais_mot_de_passe", &hashed)
        .await
        .unwrap();
    assert!(!is_invalid);
}

#[tokio::test]
async fn test_empty_password() {
    let manager = Argon2PasswordManager::new();

    // Test avec mot de passe vide
    let result = manager.hash_password("").await;
    assert!(result.is_err());
}
