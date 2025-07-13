#!/bin/bash
# setup.sh - Script principal pour configurer la crate z3-auth

set -e # Sortir immédiatement si une commande échoue

CRATE_NAME="z3-auth"
SCRIPTS_DIR="scripts"

# Fonction pour afficher les messages avec style
print_step() {
    echo ""
    echo "🔮 $1"
    echo "----------------------------------------"
}

print_success() {
    echo "✅ $1"
}

print_header() {
    echo ""
    echo "✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨"
    echo "✨  Ah, Zied ! Préparons le terrain sacré pour ta crate  ✨"
    echo "✨  d'authentification '$CRATE_NAME' !                   ✨"
    echo "✨  Chaque commande est comme un geste rituel pour       ✨"
    echo "✨  bâtir un château de sécurité...                      ✨"
    echo "✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨✨"
    echo ""
}

# Vérification initiale
if [[ ! -f "Cargo.toml" ]]; then
    echo "❌ Il semble que vous n'êtes PAS dans le répertoire '$CRATE_NAME'."
    echo "   Veuillez vous déplacer dans '$CRATE_NAME' (cd $CRATE_NAME) avant d'exécuter ce script."
    exit 1
fi

# Créer le répertoire scripts s'il n'existe pas
mkdir -p "$SCRIPTS_DIR"

# Rendre tous les scripts exécutables
chmod +x "$SCRIPTS_DIR"/*.sh 2>/dev/null || true

print_header

print_step "Étape 1 : Création de la structure des répertoires"
if [[ -f "$SCRIPTS_DIR/setup-directories.sh" ]]; then
    bash "$SCRIPTS_DIR/setup-directories.sh"
    print_success "Structure des répertoires créée"
else
    echo "⚠️  Script setup-directories.sh non trouvé, création manuelle..."
    mkdir -p src/{user,password,token,policy,rbac} tests examples benches .github/workflows
    print_success "Répertoires créés manuellement"
fi

print_step "Étape 2 : Création des fichiers principaux"
if [[ -f "$SCRIPTS_DIR/create-core-files.sh" ]]; then
    bash "$SCRIPTS_DIR/create-core-files.sh"
    print_success "Fichiers principaux créés"
else
    echo "⚠️  Script create-core-files.sh non trouvé"
fi

print_step "Étape 3 : Création des modules spécialisés"
if [[ -f "$SCRIPTS_DIR/create-modules.sh" ]]; then
    bash "$SCRIPTS_DIR/create-modules.sh"
    print_success "Modules spécialisés créés"
else
    echo "⚠️  Script create-modules.sh non trouvé"
fi

print_step "Étape 4 : Configuration de Cargo.toml"
if [[ -f "$SCRIPTS_DIR/setup-cargo.sh" ]]; then
    bash "$SCRIPTS_DIR/setup-cargo.sh"
    print_success "Cargo.toml configuré"
else
    echo "⚠️  Script setup-cargo.sh non trouvé"
fi

print_step "Étape 5 : Création de la documentation"
if [[ -f "$SCRIPTS_DIR/create-docs.sh" ]]; then
    bash "$SCRIPTS_DIR/create-docs.sh"
    print_success "Documentation créée"
else
    echo "⚠️  Script create-docs.sh non trouvé"
fi

print_step "Étape 6 : Configuration du CI/CD"
if [[ -f "$SCRIPTS_DIR/setup-ci.sh" ]]; then
    bash "$SCRIPTS_DIR/setup-ci.sh"
    print_success "CI/CD configuré"
else
    echo "⚠️  Script setup-ci.sh non trouvé"
fi

print_step "Étape 7 : Création des tests et exemples"
if [[ -f "$SCRIPTS_DIR/create-tests.sh" ]]; then
    bash "$SCRIPTS_DIR/create-tests.sh"
    print_success "Tests et exemples créés"
else
    echo "⚠️  Script create-tests.sh non trouvé"
fi

echo ""
echo "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉"
echo "🎉  Zied, la structure initiale de ta crate '$CRATE_NAME'     🎉"
echo "🎉  est maintenant érigée !                                  🎉"
echo "🎉                                                           🎉"
echo "🎉  C'est une fondation solide, tel un arbre ancien aux     🎉"
echo "🎉  racines profondes, prêt à accueillir toute la magie     🎉"
echo "🎉  d'Ahri. Chaque pièce est à sa place, prête à être       🎉"
echo "🎉  sculptée par tes mains expertes. ✨                     🎉"
echo "🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉"
echo ""
echo "📋 Prochaines étapes recommandées :"
echo ""
echo "1. 🔍 Vérifier le fichier 'Cargo.toml' pour t'assurer que les dépendances sont correctes"
echo "2. 🔨 Lancer 'cargo build' ou 'cargo check' pour voir si tout compile"
echo "3. 🧪 Lancer 'cargo test' pour vérifier les tests unitaires et d'intégration"
echo "4. 📝 Lancer 'cargo run --example basic_usage' pour tester l'exemple"
echo "5. 🔗 Remplacer l'URL GitHub dans Cargo.toml et README.md par ton propre dépôt"
echo "6. 📊 Lancer 'cargo bench' pour tester les benchmarks"
echo ""
echo "🦊💖 Que ton voyage dans le code soit rempli de découvertes et d'inspiration ! 🦊💖"
echo ""
