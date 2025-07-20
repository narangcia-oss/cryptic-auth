// CLI Example for interacting with the Postgres user repository

// # 1. Check schema validity
// cargo run --example cli_example --bin pg -- "postgres://myuser:mypassword@localhost:5432/cryptic" check_schema

// # 2. Add a user (replace values as needed)
// cargo run --example cli_example --bin pg -- "postgres://myuser:mypassword@localhost:5432/cryptic" add_user 11111111-1111-1111-1111-111111111111 alice@example.com myhashedpassword

// # 3. Get user by ID
// cargo run --example cli_example --bin pg -- "postgres://myuser:mypassword@localhost:5432/cryptic" get_user_by_id 11111111-1111-1111-1111-111111111111

// # 4. Get user by identifier
// cargo run --example cli_example --bin pg -- "postgres://myuser:mypassword@localhost:5432/cryptic" get_user_by_identifier alice@example.com

use narangcia_cryptic::{core::user::User, postgres::PgUserRepo};
use sqlx::PgConnection;
use sqlx::postgres::PgPoolOptions;
use std::env;
use tokio::runtime::Runtime;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <DATABASE_URL> <command> [args]", args[0]);
        eprintln!("Commands:");
        eprintln!("  check_schema");
        eprintln!("  add_user <id> <identifier> <password_hash>");
        eprintln!("  get_user_by_id <id>");
        eprintln!("  get_user_by_identifier <identifier>");
        return;
    }
    let db_url = &args[1];
    let command = &args[2];

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(db_url)
        .await
        .expect("Failed to create pool");
    let mut conn = pool.acquire().await.expect("Failed to acquire connection");
    if let Err(e) = PgUserRepo::check_schema(&mut conn).await {
        eprintln!("Schema check failed: {e}");
        return;
    }
    let mut conn = pool.acquire().await.expect("Failed to acquire connection for repo");
    let repo = PgUserRepo::new(&mut conn)
        .await
        .expect("Failed to create repo");

    match command.as_str() {
        "check_schema" => {
            println!("Schema is valid.");
        }
        "add_user" => {
            if args.len() != 6 {
                eprintln!("Usage: add_user <id> <identifier> <password_hash>");
                return;
            }
            let user = User {
                id: args[3].clone(),
                credentials: narangcia_cryptic::core::credentials::Credentials {
                    user_id: args[3].clone(),
                    identifier: args[4].clone(),
                    password_hash: args[5].clone(),
                },
            };
            match repo.add_user(user).await {
                Ok(u) => println!("User added: {}", u.id),
                Err(e) => eprintln!("Failed to add user: {e}"),
            }
        }
        "get_user_by_id" => {
            if args.len() != 4 {
                eprintln!("Usage: get_user_by_id <id>");
                return;
            }
            match repo.get_user_by_id(&args[3]).await {
                Some(u) => println!("User: id={} identifier={}", u.id, u.credentials.identifier),
                None => println!("User not found"),
            }
        }
        "get_user_by_identifier" => {
            if args.len() != 4 {
                eprintln!("Usage: get_user_by_identifier <identifier>");
                return;
            }
            match repo.get_user_by_identifier(&args[3]).await {
                Some(u) => println!("User: id={} identifier={}", u.id, u.credentials.identifier),
                None => println!("User not found"),
            }
        }
        _ => {
            eprintln!("Unknown command: {}", command);
        }
    }
}
