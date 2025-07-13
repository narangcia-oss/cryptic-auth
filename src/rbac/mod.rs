// src/rbac/mod.rs - Les Gardiens des Royaumes (Contrôle d'Accès Basé sur les Rôles)

//! Ce module fournit des fonctionnalités pour le contrôle d'accès basé sur les rôles (RBAC).

use std::collections::HashMap;

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Role {
    Admin,
    User,
    Moderator,
    Guest,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Permission {
    ViewUser,
    ManageUsers,
    CreateContent,
    EditContent,
    DeleteContent,
}

pub struct RbacManager {
    role_permissions: HashMap<Role, Vec<Permission>>,
}

impl Default for RbacManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RbacManager {
    pub fn new() -> Self {
        let mut rp = HashMap::new();
        // Définir les permissions pour chaque rôle
        rp.insert(Role::Admin, vec![
            Permission::ViewUser, Permission::ManageUsers,
            Permission::CreateContent, Permission::EditContent, Permission::DeleteContent
        ]);
        rp.insert(Role::User, vec![
            Permission::ViewUser, Permission::CreateContent
        ]);
        rp.insert(Role::Moderator, vec![
            Permission::ViewUser, Permission::EditContent, Permission::DeleteContent
        ]);
        rp.insert(Role::Guest, vec![
            Permission::ViewUser
        ]);
        Self { role_permissions: rp }
    }

    /// Vérifie si un rôle donné a une certaine permission.
    pub fn has_permission(&self, role: &Role, permission: &Permission) -> bool {
        self.role_permissions
            .get(role)
            .map(|perms| perms.contains(permission))
            .unwrap_or(false)
    }

    /// Vérifie si un utilisateur (avec ses rôles) a une certaine permission.
    pub fn user_has_permission(&self, user_roles: &[Role], permission: &Permission) -> bool {
        user_roles.iter().any(|role| self.has_permission(role, permission))
    }
}
