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
