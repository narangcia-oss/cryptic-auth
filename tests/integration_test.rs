use cryptic::AuthService;

#[tokio::test]
async fn test_auth_service_signup_not_implemented() {
    let auth_service = AuthService::default();

    let credentials = cryptic::core::credentials::Credentials::from_plain_password(
        auth_service.password_manager.as_ref(),
        "test_user".to_string(),
        cryptic::core::credentials::PlainPassword::new("plain_password".to_string()),
    )
    .await;

    let credentials = credentials.expect("Failed to create credentials");
    let user = cryptic::core::user::User::new("test_user".to_string(), credentials);

    let result = auth_service.signup(user).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_auth_service_login_success() {
    // Create a user first
    let auth_service = AuthService::default();

    let credentials = cryptic::core::credentials::Credentials::from_plain_password(
        auth_service.password_manager.as_ref(),
        "test_user".to_string(),
        cryptic::core::credentials::PlainPassword::new("plain_password".to_string()),
    )
    .await;

    let credentials = credentials.expect("Failed to create credentials");
    let user = cryptic::core::user::User::new("test_user_id".to_string(), credentials);

    let auth_service = cryptic::AuthService::default();

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
    let auth_service = cryptic::AuthService::default();

    let result = auth_service
        .login_with_credentials("nonexistent_user", "wrong_password")
        .await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().to_string(),
        "Invalid credentials provided."
    );
}
