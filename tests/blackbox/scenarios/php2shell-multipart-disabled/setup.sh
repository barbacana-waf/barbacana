#!/usr/bin/env bash
# Generates the PHP2Shell multipart request-shape fixtures (same shapes as
# blocking-php2shell-multipart), hand-built with CRLF line endings.
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

# Restricted-file upload (.htaccess) for the sibling-leaf check: CRS's
# restricted file upload list, under file-upload-limits-executable.
{
  printf -- '--%s\r\nContent-Disposition: form-data; name="upload"; filename=".htaccess"\r\nContent-Type: text/plain\r\n\r\nDeny from all\r\n' "$B"
  printf -- '--%s--\r\n' "$B"
} > "$DIR/htaccess-upload.bin"
