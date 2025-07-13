#!/bin/bash
# scripts/setup-directories.sh - Créer la structure des répertoires

set -e

echo "🔮 Création de la structure des répertoires..."

# Variables
SRC_DIR="src"
TESTS_DIR="tests"
EXAMPLES_DIR="examples"
BENCHES_DIR="benches"
GITHUB_WORKFLOWS_DIR=".github/workflows"

# Créer les répertoires principaux
mkdir -p "$SRC_DIR/user"
mkdir -p "$SRC_DIR/password"
mkdir -p "$SRC_DIR/token"
mkdir -p "$SRC_DIR/policy"
mkdir -p "$SRC_DIR/rbac"
mkdir -p "$TESTS_DIR"
mkdir -p "$EXAMPLES_DIR"
mkdir -p "$BENCHES_DIR"
mkdir -p "$GITHUB_WORKFLOWS_DIR"

echo "  ✓ Répertoires créés avec succès !"
