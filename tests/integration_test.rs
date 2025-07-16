use z3_auth::Z3AuthService;

#[tokio::test]
async fn test_auth_service_signup_not_implemented() {
    let password_manager = Box::new(z3_auth::core::password::Argon2PasswordManager::default());
    let user_repo = Box::new(z3_auth::core::user::persistence::InMemoryUserRepo::new());

    let credentials = z3_auth::core::credentials::Credentials::from_plain_password(
        password_manager.as_ref(),
        "test_user".to_string(),
        z3_auth::core::credentials::PlainPassword::new("plain_password".to_string()),
    )
    .await;

    let credentials = credentials.expect("Failed to create credentials");
    let user = z3_auth::core::user::User::new("test_user".to_string(), credentials);

    let auth_service = Z3AuthService::new(Some(password_manager), Some(user_repo))
        .expect("Failed to create auth service");

    let result = auth_service.signup(user).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_auth_service_login_success() {
    let password_manager = Box::new(z3_auth::core::password::Argon2PasswordManager::default());
    let user_repo = Box::new(z3_auth::core::user::persistence::InMemoryUserRepo::new());

    // Create a user first
    let credentials = z3_auth::core::credentials::Credentials::from_plain_password(
        password_manager.as_ref(),
        "test_user".to_string(),
        z3_auth::core::credentials::PlainPassword::new("plain_password".to_string()),
    )
    .await;

    let credentials = credentials.expect("Failed to create credentials");
    let user = z3_auth::core::user::User::new("test_user_id".to_string(), credentials);

    let auth_service = z3_auth::Z3AuthService::new(Some(password_manager), Some(user_repo))
        .expect("Failed to create auth service");

    // Sign up the user first
    let signup_result = auth_service.signup(user).await;
    assert!(signup_result.is_ok());

    // Now test login with correct credentials
    let login_result = auth_service
        .login_with_credentials("test_user", "plain_password")
        .await;
    assert!(login_result.is_ok());
}

#[tokio::test]
async fn test_auth_service_login_invalid_credentials() {
    let auth_service = z3_auth::Z3AuthService::new(
        Some(Box::new(
            z3_auth::core::password::Argon2PasswordManager::default(),
        )),
        Some(Box::new(
            z3_auth::core::user::persistence::InMemoryUserRepo::new(),
        )),
    )
    .expect("Failed to create auth service");

    let result = auth_service
        .login_with_credentials("nonexistent_user", "wrong_password")
        .await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Invalid credentials provided."
    );
}
