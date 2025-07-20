pub mod in_memory;

pub mod store;
pub mod traits;

// Re-export the main types and traits for easier access
pub use in_memory::InMemoryUserRepo;

pub use store::PersistentUsers;
pub use traits::UserRepository;
