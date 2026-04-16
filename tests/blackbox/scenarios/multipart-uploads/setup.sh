#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/tests/fixtures"
mkdir -p "$DIR"

# Simple text content — avoids CRS false positives on binary data.
printf 'valid image content here' > "$DIR/valid.png"
printf 'FAKEJPG' > "$DIR/shell.php.jpg"
printf 'plain text content' > "$DIR/test.txt"
dd if=/dev/zero bs=2048 count=1 2>/dev/null > "$DIR/large.bin"
