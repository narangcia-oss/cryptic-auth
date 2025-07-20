//! # Basic CLI Example for Narangcia Cryptic
//!
//! This example demonstrates the key features of the `narangcia-cryptic` authentication crate
//! through a command-line interface.
//!
//! ## Features Demonstrated
//!
//! - **User Registration**: Create new user accounts with hashed passwords
//! - **User Login**: Authenticate users and generate JWT tokens
//! - **Token Validation**: Verify access tokens and extract claims
//! - **Token Refresh**: Generate new access tokens using refresh tokens
//! - **Interactive Mode**: Run multiple commands in a single session
//!
//! ## Usage
//!
//! ### Build and Run
//!
//! ```bash
//! cargo run --manifest-path examples/cli_example/Cargo.toml -- [COMMAND]
//! ```
//!
//! ### Available Commands
//!
//! #### 1. User Registration
//! ```bash
//! cargo run --manifest-path examples/cli_example/Cargo.toml -- signup --username alice --password secret123
//! ```
//!
//! #### 2. User Login
//! ```bash
//! cargo run --manifest-path examples/cli_example/Cargo.toml -- login --username alice --password secret123
//! ```
//!
//! #### 3. Token Validation
//! ```bash
//! cargo run --manifest-path examples/cli_example/Cargo.toml -- validate-token --token "your_jwt_token_here"
//! ```
//!
//! #### 4. Token Refresh
//! ```bash
//! cargo run --manifest-path examples/cli_example/Cargo.toml -- refresh-token --refresh-token "your_refresh_token_here"
//! ```
//!
//! #### 5. Interactive Mode (Recommended)
//! ```bash
//! cargo run --manifest-path examples/cli_example/Cargo.toml -- interactive
//! ```
//!
//! In interactive mode, you can run multiple commands in a single session, which allows
//! you to signup a user and then immediately login with the same user since they share
//! the same AuthService instance.
//!
//! Example interactive session:
//! ```
//! cryptic> signup alice
//! Enter password: secret123
//! ✅ User 'alice' successfully registered!
//! cryptic> login alice
//! Enter password: secret123
//! ✅ Login successful!
//! 👤 User ID: 12345678-1234-1234-1234-123456789abc
//! 🎫 Access Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
//! 🔄 Refresh Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
//! cryptic> validate eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
//! ✅ Token is valid!
//! 👤 Subject: 12345678-1234-1234-1234-123456789abc
//! ⏰ Expires at: 1234567890
//! cryptic> exit
//! 👋 Goodbye!
//! ```
//!
//! ## Important Notes
//!
//! - **In-Memory Storage**: This example uses in-memory storage, so data is not persisted
//!   between different CLI command executions. Use interactive mode for complete workflows.
//! - **Security**: Passwords are prompted securely when not provided as arguments
//! - **JWT Tokens**: Generated tokens include both access and refresh tokens with proper claims
//!
//! ## Architecture
//!
//! This example showcases the modular architecture of `narangcia-cryptic`:
//! - `AuthService`: Main service orchestrating authentication operations
//! - `Argon2PasswordManager`: Secure password hashing using Argon2
//! - `InMemoryUserRepo`: Simple in-memory user storage
//! - `JwtTokenService`: JWT token generation and validation
//!

use clap::{Parser, Subcommand};
use narangcia_cryptic::{
    AuthService,
    core::{
        credentials::{Credentials, PlainPassword},
        user::User,
    },
};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "cryptic-cli")]
#[command(about = "A CLI example for the narangcia-cryptic authentication service")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new user
    Signup {
        /// Username/identifier for the user
        #[arg(short, long)]
        username: String,
        /// Password for the user (will be prompted if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Login with existing credentials
    Login {
        /// Username/identifier for login
        #[arg(short, long)]
        username: String,
        /// Password for login (will be prompted if not provided)
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Validate a token
    ValidateToken {
        /// The access token to validate
        #[arg(short, long)]
        token: String,
    },
    /// Refresh an access token
    RefreshToken {
        /// The refresh token to use
        #[arg(short, long)]
        refresh_token: String,
    },
    /// Interactive mode - run multiple commands
    Interactive,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    let cli = Cli::parse();
    let auth_service = AuthService::default();

    match cli.command {
        Commands::Signup { username, password } => {
            let password = get_password_input(password, "Enter password for signup: ")?;
            signup_user(&auth_service, &username, &password).await?;
        }
        Commands::Login { username, password } => {
            let password = get_password_input(password, "Enter password for login: ")?;
            login_user(&auth_service, &username, &password).await?;
        }
        Commands::ValidateToken { token } => {
            validate_token(&auth_service, &token).await?;
        }
        Commands::RefreshToken { refresh_token } => {
            refresh_access_token(&auth_service, &refresh_token).await?;
        }
        Commands::Interactive => {
            run_interactive_mode(&auth_service).await?;
        }
    }

    Ok(())
}

fn get_password_input(password: Option<String>, prompt: &str) -> Result<String, io::Error> {
    match password {
        Some(pwd) => Ok(pwd),
        None => {
            print!("{}", prompt);
            io::stdout().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            Ok(input.trim().to_string())
        }
    }
}

async fn signup_user(
    auth_service: &AuthService,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Creating new user account...");

    let credentials = Credentials::from_plain_password(
        auth_service.password_manager.as_ref(),
        username.to_string(),
        PlainPassword::new(password.to_string()),
    )
    .await?;

    let user = User::new(uuid::Uuid::new_v4().to_string(), credentials);

    match auth_service.signup(user).await {
        Ok(_) => {
            println!("✅ User '{}' successfully registered!", username);
        }
        Err(e) => {
            eprintln!("❌ Signup failed: {}", e);
        }
    }

    Ok(())
}

async fn login_user(
    auth_service: &AuthService,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔑 Attempting to log in...");

    match auth_service
        .login_with_credentials_and_tokens(username, password)
        .await
    {
        Ok((user, tokens)) => {
            println!("✅ Login successful!");
            println!("👤 User ID: {}", user.id);
            println!("🎫 Access Token: {}", tokens.access_token);
            println!("🔄 Refresh Token: {}", tokens.refresh_token);
        }
        Err(e) => {
            eprintln!("❌ Login failed: {}", e);
        }
    }

    Ok(())
}

async fn validate_token(
    auth_service: &AuthService,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Validating token...");

    match auth_service.validate_access_token(token).await {
        Ok(claims) => {
            println!("✅ Token is valid!");
            println!("👤 Subject: {}", claims.get_subject());
            println!("⏰ Expires at: {}", claims.get_expiration());
        }
        Err(e) => {
            eprintln!("❌ Token validation failed: {}", e);
        }
    }

    Ok(())
}

async fn refresh_access_token(
    auth_service: &AuthService,
    refresh_token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔄 Refreshing access token...");

    match auth_service.refresh_access_token(refresh_token).await {
        Ok(tokens) => {
            println!("✅ Token refreshed successfully!");
            println!("🎫 New Access Token: {}", tokens.access_token);
            println!("🔄 New Refresh Token: {}", tokens.refresh_token);
        }
        Err(e) => {
            eprintln!("❌ Token refresh failed: {}", e);
        }
    }

    Ok(())
}

async fn run_interactive_mode(
    auth_service: &AuthService,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 Welcome to Cryptic Interactive Mode!");
    println!("Available commands:");
    println!("  1. signup <username> - Register a new user");
    println!("  2. login <username> - Login with credentials");
    println!("  3. validate <token> - Validate an access token");
    println!("  4. refresh <refresh_token> - Refresh an access token");
    println!("  5. help - Show this help message");
    println!("  6. exit - Exit interactive mode");
    println!();

    loop {
        print!("cryptic> ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "signup" => {
                if parts.len() < 2 {
                    println!("Usage: signup <username>");
                    continue;
                }
                let username = parts[1];
                let password = get_password_input(None, "Enter password: ")?;
                if let Err(e) = signup_user(auth_service, username, &password).await {
                    eprintln!("Error: {}", e);
                }
            }
            "login" => {
                if parts.len() < 2 {
                    println!("Usage: login <username>");
                    continue;
                }
                let username = parts[1];
                let password = get_password_input(None, "Enter password: ")?;
                if let Err(e) = login_user(auth_service, username, &password).await {
                    eprintln!("Error: {}", e);
                }
            }
            "validate" => {
                if parts.len() < 2 {
                    println!("Usage: validate <token>");
                    continue;
                }
                let token = parts[1];
                if let Err(e) = validate_token(auth_service, token).await {
                    eprintln!("Error: {}", e);
                }
            }
            "refresh" => {
                if parts.len() < 2 {
                    println!("Usage: refresh <refresh_token>");
                    continue;
                }
                let refresh_token = parts[1];
                if let Err(e) = refresh_access_token(auth_service, refresh_token).await {
                    eprintln!("Error: {}", e);
                }
            }
            "help" => {
                println!("Available commands:");
                println!("  signup <username> - Register a new user");
                println!("  login <username> - Login with credentials");
                println!("  validate <token> - Validate an access token");
                println!("  refresh <refresh_token> - Refresh an access token");
                println!("  help - Show this help message");
                println!("  exit - Exit interactive mode");
            }
            "exit" => {
                println!("👋 Goodbye!");
                break;
            }
            _ => {
                println!(
                    "Unknown command: {}. Type 'help' for available commands.",
                    parts[0]
                );
            }
        }
    }

    Ok(())
}
