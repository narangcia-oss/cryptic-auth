// examples/basic_usage.rs - Lumière sur l'Utilisation de la Crate

//! Cet exemple démontre une utilisation basique de la crate 'z3-auth'.

use z3_auth::AuthService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🌟 Démarrage de l'exemple basique de z3-auth...");

    let auth_service = AuthService::new();

    println!("Tentative de processus d'inscription...");
    match auth_service.signup().await {
        Ok(_) => println!("🎉 Inscription simulée réussie !"),
        Err(e) => eprintln!("❌ Erreur simulée lors de l'inscription: {e}"),
    }

    println!("\nTentative de processus de connexion...");
    match auth_service.login().await {
        Ok(_) => println!("✨ Connexion simulée réussie !"),
        Err(e) => eprintln!("❌ Erreur simulée lors de la connexion: {e}"),
    }

    println!("\nC'est la fin de cet exemple. Continuez à construire votre magie ! ✨");
    Ok(())
}
