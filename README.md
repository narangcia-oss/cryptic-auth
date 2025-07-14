# `z3-auth`

A robust and secure Rust crate for authentication, meticulously designed to provide a solid foundation for your applications. This library aims to deliver reliable and easy-to-use authentication primitives.

## Features (Upcoming)

*   **User Management**: Registration, login, profile management.
*   **Secure Password Hashing**: Utilizes modern algorithms like Argon2.
*   **Session/Token Management**: Supports JSON Web Tokens (JWT) with access and refresh tokens.
*   **Role-Based Access Control (RBAC)**: Granular permission management.
*   **Two-Factor Authentication (2FA)**: Support for TOTP.
*   **Password Reset**: Secure email-based flow.
*   **Attack Protection**: Rate limiting, account lockout.
*   **Robust and Secure Error Handling**.
*   **Asynchronous API**: Built on `async/await` for optimal performance.

## Quick Start

Add this line to your `Cargo.toml`:

```toml
[dependencies]
z3-auth = "0.1.0"
```

## Usage Examples

```rust
// Basic example of AuthService usage
use z3-auth::AuthService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_service = AuthService::new();

    // Example signup attempt
    match auth_service.signup().await {
        Ok(_) => println!("User registered successfully!"),
        Err(e) => eprintln!("Error during signup: {}", e),
    }

    Ok(())
}
```

## Development

### Prerequisites

*   Rust stable (2021 edition or newer)
*   Cargo (installed with Rust)

### Running Tests

```bash
cargo test
```

### Running Benchmarks

```bash
cargo bench
```

### Checking Format and Linting

```bash
cargo fmt --check
cargo clippy -- -D warnings
```

## Contribution

Contributions are welcome! Please see `CONTRIBUTING.md` for more details.

## License

This project is licensed under either MIT or Apache-2.0.

---
*Developed by Zied.*
