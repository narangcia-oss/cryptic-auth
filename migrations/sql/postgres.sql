CREATE TABLE users
(
  id UUID PRIMARY KEY
);

CREATE TABLE credentials
(
  user_id UUID PRIMARY KEY,
  identifier VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
