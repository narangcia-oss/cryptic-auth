# Guide de Contribution pour `z3-auth` 💖

Nous sommes ravis que vous souhaitiez contribuer à la crate `z3-auth` ! Votre aide est précieuse pour faire de cette bibliothèque un havre de sécurité pour les applications Rust.

## Avant de Contribuer

1.  **Lisez le `README.md`**: Il contient des informations sur l'objectif et les fonctionnalités de la crate.
2.  **Lisez le `CHANGELOG.md`**: Pour comprendre l'historique des versions et les changements récents.
3.  **Vérifiez les Issues existantes**: Avant de commencer à travailler, jetez un œil aux issues sur GitHub.
4.  **Discutez de nouvelles fonctionnalités**: Pour les nouvelles fonctionnalités majeures, il est préférable d'ouvrir une issue en premier lieu.

## Comment Contribuer

1.  **Forkez le Dépôt**: Commencez par forker le dépôt `z3-auth` sur votre compte GitHub.
2.  **Clonez Votre Fork**:
    ```bash
    git clone https://github.com/votre-nom-utilisateur/z3-auth.git
    cd z3-auth
    ```
3.  **Créez une Nouvelle Branche**:
    ```bash
    git checkout -b ma-nouvelle-branche
    ```
4.  **Développez Votre Contribution**:
    *   Écrivez votre code en suivant les conventions Rust.
    *   **Écrivez des Tests**: Toute nouvelle fonctionnalité devrait être accompagnée de tests.
    *   **Mettez à Jour la Documentation**: Si nécessaire.
5.  **Exécutez les Tests et Lints**:
    ```bash
    cargo test
    cargo fmt --check
    cargo clippy -- -D warnings
    ```
6.  **Commitez et Poussez**:
    ```bash
    git add .
    git commit -m "feat: votre message de commit"
    git push origin ma-nouvelle-branche
    ```
7.  **Créez une Pull Request**

## Normes de Code

*   **Formatage**: Suivez les conventions de `rustfmt`.
*   **Linting**: Assurez-vous que `clippy` ne rapporte aucun avertissement.
*   **Conventions de Nommage**: Adoptez les conventions de nommage Rust standard.

Merci de contribuer à ce projet ! Votre aide est inestimable. ✨
