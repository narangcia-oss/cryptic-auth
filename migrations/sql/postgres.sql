--
-- Cryptic Database Schema
--
-- This schema defines the core tables for user authentication and credential management in the Cryptic system.
--
-- Tables:
--   - cryptic_users: Stores user identities (UUID primary key).
--   - cryptic_credentials: Stores user credentials, including unique identifier and password hash.
--
-- Relationships:
--   - Each credential is linked to a user via user_id (foreign key).
--   - Deleting a user cascades to delete their credentials.
--
-- Notes:
--   - Identifiers (e.g., email, username) must be unique.
--   - Passwords are stored as secure hashes, not plaintext.
--
CREATE TABLE cryptic_users
(
  id UUID PRIMARY KEY
);

CREATE TABLE cryptic_credentials
(
  user_id UUID PRIMARY KEY,
  identifier VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES cryptic_users(id) ON DELETE CASCADE
);
