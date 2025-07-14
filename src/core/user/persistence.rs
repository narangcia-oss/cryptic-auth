// Re-export persistence module items for backward compatibility
// This maintains the same public API while organizing the code into separate modules

pub use self::persistence::{InMemoryUserRepo, PersistentUsers, UserRepository};

pub mod persistence {
    pub use super::super::persistence::*;
}
