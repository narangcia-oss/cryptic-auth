//! Persistence layer for user data.
//!
//! This module provides abstractions and implementations for user data storage and retrieval.
//! It includes in-memory and persistent storage backends, as well as traits for extensibility.
//!
//! # Modules
//! - [`in_memory`]: In-memory user repository for testing and ephemeral use.
//! - [`store`]: Persistent user storage implementation.
//! - [`traits`]: Core traits for user repository abstraction.
//!
//! # Re-exports
//! The most common types and traits are re-exported for convenience.

/// In-memory user repository implementation.
///
/// This module provides a user repository that stores user data in memory.
/// Useful for testing and non-persistent scenarios.
pub mod in_memory;

/// Persistent user storage implementation.
///
/// This module provides a user repository backed by a persistent data store (e.g., database).
pub mod store;

/// Core traits for user repository abstraction.
///
/// This module defines the [`UserRepository`] trait and related abstractions for user data operations.
pub mod traits;

// Re-export the main types and traits for easier access

/// Re-export of the in-memory user repository for convenient access.
pub use in_memory::InMemoryUserRepo;

/// Re-export of the persistent user storage type for convenient access.
pub use store::PersistentUsers;

/// Re-export of the core user repository trait for convenient access.
pub use traits::UserRepository;
