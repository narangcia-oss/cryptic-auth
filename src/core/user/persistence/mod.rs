pub mod in_memory;
#[cfg(feature = "sqlx")]
pub mod pg_user_repo;
pub mod store;
pub mod traits;

// Re-export the main types and traits for easier access
pub use in_memory::InMemoryUserRepo;
#[cfg(feature = "sqlx")]
pub use pg_user_repo::PgUserRepo;
pub use store::PersistentUsers;
pub use traits::UserRepository;
