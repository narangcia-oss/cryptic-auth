//! # Unified Authentication Example
//!
//! This example demonstrates how to use the new unified authentication system
//! with `LoginMethod` and `SignupMethod` enums to support different authentication methods.
//!
//! ## Features Demonstrated
//! - Unified signup with credentials
//! - Unified login with credentials
//! - OAuth2 authentication (setup example, requires configuration)
//!
//! ## Usage
//! ```bash
//! cargo run --example unified_auth_example
//! ```

use narangcia_cryptic::{AuthService, LoginMethod, SignupMethod};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Unified Authentication System Example");
    println!("=========================================\n");

    // Initialize the authentication service
    let auth_service = AuthService::default();

    // 1. Signup with credentials
    println!("1. 📝 Signing up a new user with credentials...");
    let signup_result = auth_service
        .signup(SignupMethod::Credentials {
            identifier: "alice@example.com".to_string(),
            password: "super_secure_password123".to_string(),
        })
        .await;

    match signup_result {
        Ok((user, tokens)) => {
            println!("   ✅ Signup successful!");
            println!("   👤 User ID: {}", user.id);
            if let Some(creds) = &user.credentials {
                println!("   📧 Email: {}", creds.identifier);
            }
            println!("   🎫 Access Token: {}", tokens.access_token);
            println!("   🔄 Refresh Token: {}", tokens.refresh_token);
        }
        Err(e) => {
            println!("   ❌ Signup failed: {e}");
            return Err(e.into());
        }
    }

    println!();

    // 2. Login with credentials
    println!("2. 🔑 Logging in with credentials...");
    let login_result = auth_service
        .login(LoginMethod::Credentials {
            identifier: "alice@example.com".to_string(),
            password: "super_secure_password123".to_string(),
        })
        .await;

    match login_result {
        Ok((user, tokens)) => {
            println!("   ✅ Login successful!");
            println!("   👤 User ID: {}", user.id);
            if let Some(creds) = &user.credentials {
                println!("   📧 Email: {}", creds.identifier);
            }
            println!("   🎫 New Access Token: {}", tokens.access_token);
            println!("   🔄 New Refresh Token: {}", tokens.refresh_token);
        }
        Err(e) => {
            println!("   ❌ Login failed: {e}");
            return Err(e.into());
        }
    }

    println!();

    // 3. Demonstrate failed login
    println!("3. ❌ Attempting login with wrong credentials...");
    let failed_login = auth_service
        .login(LoginMethod::Credentials {
            identifier: "alice@example.com".to_string(),
            password: "wrong_password".to_string(),
        })
        .await;

    match failed_login {
        Ok(_) => println!("   ⚠️  Unexpected: Login should have failed!"),
        Err(e) => println!("   ✅ Expected failure: {e}"),
    }

    println!();

    // 4. OAuth2 example (commented out since it requires actual provider setup)
    println!("4. 🔗 OAuth2 Authentication Example (Setup Required)");
    println!("   To use OAuth2 authentication, you would do:");
    println!("   ```rust");
    println!("   // For signup:");
    println!("   auth_service.signup(SignupMethod::OAuth2 {{");
    println!("       provider: OAuth2Provider::Google,");
    println!("       code: \"authorization_code_from_provider\".to_string(),");
    println!("       state: \"csrf_protection_state\".to_string(),");
    println!("   }}).await");
    println!();
    println!("   // For login:");
    println!("   auth_service.login(LoginMethod::OAuth2 {{");
    println!("       provider: OAuth2Provider::Google,");
    println!("       code: \"authorization_code_from_provider\".to_string(),");
    println!("       state: \"csrf_protection_state\".to_string(),");
    println!("   }}).await");
    println!("   ```");

    println!();
    println!("✨ Example completed successfully!");
    println!("📚 The unified authentication system provides:");
    println!("   - Single `login()` method for all authentication types");
    println!("   - Single `signup()` method for all registration types");
    println!("   - Type-safe enum-based method selection");
    println!("   - Consistent return types (User, TokenPair)");
    println!("   - Support for credentials and OAuth2 authentication");

    Ok(())
}
