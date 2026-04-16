#!/usr/bin/env bash
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/tests/fixtures"
mkdir -p "$DIR"
dd if=/dev/zero bs=1 count=10000 2>/dev/null | gzip > "$DIR/bomb.gz"
