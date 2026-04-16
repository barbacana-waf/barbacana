#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/tests/fixtures"
mkdir -p "$DIR"

printf 'FAKEJPG' > "$DIR/shell.php.jpg"
