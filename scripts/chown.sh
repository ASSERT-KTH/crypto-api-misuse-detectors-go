#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TARGET_DIR="${1:-$REPO_ROOT}"
sudo chown -R "$(whoami):$(whoami)" "$TARGET_DIR"
