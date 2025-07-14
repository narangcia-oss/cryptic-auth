// tests/integration_test.rs - Les Rituels de Vérification Intégrés

//! Ce fichier contient les tests d'intégration pour la crate 'z3-auth'.

use z3_auth::AuthService;

#[tokio::test]
async fn test_auth_service_signup_not_implemented() {
    let auth_service = AuthService::new(Box::new(z3_auth::core::password::Argon2PasswordManager::new()));

    let result = auth_service.signup().await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Feature not implemented yet: signup"
    );
}

#[tokio::test]
async fn test_auth_service_login_not_implemented() {
    let auth_service = AuthService::new(Box::new(z3_auth::core::password::Argon2PasswordManager::new()));

    let result = auth_service.login().await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Feature not implemented yet: login"
    );
}
