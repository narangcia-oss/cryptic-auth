# Unified Authentication System Refactoring

This document summarizes the refactoring of the authentication service to use enums for different login and signup methods.

## Overview

The refactoring introduces a unified authentication system that consolidates different authentication methods into single `login()` and `signup()` methods using enums to specify the authentication type.

## Key Changes

### 1. New Enums

#### `LoginMethod`

```rust
pub enum LoginMethod {
    /// Login using username/email and password credentials.
    Credentials {
        identifier: String,
        password: String,
    },
    /// Login using OAuth2 authorization code flow.
    OAuth2 {
        provider: OAuth2Provider,
        code: String,
        state: String,
    },
}
```

#### `SignupMethod`

```rust
pub enum SignupMethod {
    /// Register using credentials (username/email and password).
    Credentials {
        identifier: String,
        password: String,
    },
    /// Register via OAuth2 (will create account if it doesn't exist).
    OAuth2 {
        provider: OAuth2Provider,
        code: String,
        state: String,
    },
}
```

### 2. Unified Methods

#### `AuthService::login()`

- **Single entry point** for all login operations
- Takes a `LoginMethod` enum parameter
- Returns `Result<(User, TokenPair), AuthError>` for all methods
- Supports both credentials and OAuth2 authentication

#### `AuthService::signup()`

- **Single entry point** for all signup operations
- Takes a `SignupMethod` enum parameter
- Returns `Result<(User, TokenPair), AuthError>` for all methods
- Supports both credentials and OAuth2 registration

### 3. Deprecated Methods

The following methods are now deprecated but remain available for backward compatibility:

- `login_with_credentials()`
- `login_with_credentials_and_tokens()`
- `login_with_oauth2()`
- `signup_user()` (renamed from `signup()`)

## Benefits

### 1. **Simplified API**

- Only 2 methods instead of 4+ different login/signup variants
- Consistent return types across all authentication methods
- Type-safe method selection through enums

### 2. **Better Developer Experience**

- Clear separation of authentication methods
- Autocomplete-friendly enum variants
- Self-documenting code through descriptive enum names

### 3. **Extensibility**

- Easy to add new authentication methods by extending the enums
- Centralized logic for each authentication type
- Consistent error handling across all methods

### 4. **Maintainability**

- Single place to modify authentication logic
- Reduced code duplication
- Clear separation of concerns

## Usage Examples

### Credentials Authentication

```rust
// Signup
let (user, tokens) = auth_service
    .signup(SignupMethod::Credentials {
        identifier: "alice@example.com".to_string(),
        password: "secure_password".to_string(),
    })
    .await?;

// Login
let (user, tokens) = auth_service
    .login(LoginMethod::Credentials {
        identifier: "alice@example.com".to_string(),
        password: "secure_password".to_string(),
    })
    .await?;
```

### OAuth2 Authentication

```rust
// Signup/Login (OAuth2 creates account if it doesn't exist)
let (user, tokens) = auth_service
    .signup(SignupMethod::OAuth2 {
        provider: OAuth2Provider::Google,
        code: "auth_code_from_provider".to_string(),
        state: "csrf_state".to_string(),
    })
    .await?;

let (user, tokens) = auth_service
    .login(LoginMethod::OAuth2 {
        provider: OAuth2Provider::Google,
        code: "auth_code_from_provider".to_string(),
        state: "csrf_state".to_string(),
    })
    .await?;
```

## Migration Guide

### For Application Code

Replace old method calls with new enum-based calls:

**Before:**

```rust
// Old signup
let user = User::with_plain_password(...).await?;
auth_service.signup(user).await?;

// Old login
let (user, tokens) = auth_service
    .login_with_credentials_and_tokens("alice", "password")
    .await?;
```

**After:**

```rust
// New unified signup
let (user, tokens) = auth_service
    .signup(SignupMethod::Credentials {
        identifier: "alice".to_string(),
        password: "password".to_string(),
    })
    .await?;

// New unified login
let (user, tokens) = auth_service
    .login(LoginMethod::Credentials {
        identifier: "alice".to_string(),
        password: "password".to_string(),
    })
    .await?;
```

### For Library Users

The deprecated methods are still available and will continue to work, but it's recommended to migrate to the new unified methods for better consistency and future-proofing.

## Updated Files

- `src/auth_service.rs` - Added enums and unified methods
- `src/web_axum.rs` - Updated HTTP handlers to use new methods
- `examples/cli_example/src/main.rs` - Updated CLI example
- `examples/unified_auth_example.rs` - New example demonstrating the unified system
- `tests/all_tests.rs` - Updated tests to use new methods
- `benches/all_benches.rs` - Updated benchmarks to use new methods

## Backward Compatibility

All existing code will continue to work without modification due to the deprecated methods that wrap the new implementation. However, users will see deprecation warnings encouraging them to migrate to the new unified methods.

## Future Enhancements

The enum-based approach makes it easy to add new authentication methods:

- WebAuthn/FIDO2 authentication
- Magic link authentication
- SMS/Phone-based authentication
- Multi-factor authentication combinations
- Custom authentication providers

Each new method can be added as a new enum variant without breaking existing code.
