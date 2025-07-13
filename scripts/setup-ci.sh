#!/bin/bash
# scripts/setup-ci.sh - Configurer GitHub Actions CI

set -e

echo "☁️ Configuration de GitHub Actions CI..."

GITHUB_WORKFLOWS_DIR=".github/workflows"

# CI workflow
echo "  - Création du workflow CI..."
cat > "$GITHUB_WORKFLOWS_DIR/ci.yml" << 'EOF'
# .github/workflows/ci.yml - Le Cycle Infini de l'Excellence

name: Rust CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  CARGO_TERM_COLOR: always

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Install Rust toolchain
      uses: dtolnay/rust-toolchain@stable
      with:
        toolchain: stable
        components: clippy, rustfmt

    - name: Run cargo fmt check
      run: cargo fmt --check

    - name: Run cargo clippy
      run: cargo clippy -- -D warnings

    - name: Run cargo test
      run: cargo test --workspace
EOF

echo "  ✓ GitHub Actions CI configuré avec succès !"
