#!/usr/bin/env bash
# Generates the CVE-2026-109618 ("PHP2Shell") multipart request-shape
# fixtures. Hand-built with CRLF line endings so the part headers are
# exact; every body stays well under the default 128KB max_inspect_size.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/tests/fixtures"
mkdir -p "$DIR"
B="BarbacanaShapeBoundary"

# One part with 4001 header lines (Content-Disposition + 4000 padding):
# over the 4000-line part-header cap.
{
  printf -- '--%s\r\nContent-Disposition: form-data; name="x"\r\n' "$B"
  for i in $(seq 0 3999); do printf 'X-P%d: a\r\n' "$i"; done
  printf '\r\nv\r\n--%s--\r\n' "$B"
} > "$DIR/header-flood.bin"

# n empty file controls (file inputs left empty) with nested field names.
empty_controls() {
  printf -- '--%s\r\nContent-Disposition: form-data; name="title"\r\n\r\nhello\r\n' "$B"
  for i in $(seq 1 "$1"); do
    printf -- '--%s\r\nContent-Disposition: form-data; name="doc%d[a][b]"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n' "$B" "$i"
  done
  printf -- '--%s--\r\n' "$B"
}
empty_controls 21 > "$DIR/empty-file-controls.bin"
empty_controls 20 > "$DIR/twenty-empty-file-controls.bin"

printf 'Meeting notes: ship the release on Thursday.\n' > "$DIR/notes.txt"
