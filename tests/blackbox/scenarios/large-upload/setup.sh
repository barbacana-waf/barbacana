#!/usr/bin/env bash
# Generates the large-upload fixtures. They are not committed: the biggest is
# 100MB. Contents are hostile-looking text on purpose; the rules do not read
# uploaded files, and the window must not count them.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)/tests/fixtures"
mkdir -p "$DIR"
B="BarbacanaShapeBoundary"

hostile="' OR '1'='1' -- <script>alert(1)</script> ../../etc/passwd; cat /etc/passwd"

# gen N prints N bytes of hostile-looking text. yes dies of SIGPIPE when head
# is satisfied, which pipefail would report as a failure.
gen() { yes "$hostile" | head -c "$1" || true; }

text_file() { gen "$(($2 * 1024 * 1024))" > "$1"; }
text_file "$DIR/upload-5mb.txt" 5
text_file "$DIR/upload-100mb.txt" 100

# A JSON body of about 200KB: over the default 128KB window.
{
  printf '{"data":"'
  head -c 204800 /dev/zero | tr '\0' 'a'
  printf '"}'
} > "$DIR/big.json"
# The same shape with an attack at the start, and one after the window.
{
  printf '{"q":"1 UNION SELECT password FROM users","data":"'
  head -c 204800 /dev/zero | tr '\0' 'a'
  printf '"}'
} > "$DIR/big-attack-first.json"
{
  printf '{"data":"'
  head -c 204800 /dev/zero | tr '\0' 'a'
  printf '","q":"1 UNION SELECT password FROM users"}'
} > "$DIR/big-attack-last.json"

# 21 empty file controls placed after a 2MB upload: the shape the php2shell
# empty-file-control cap counts, behind bytes that must not hide it.
{
  printf -- '--%s\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\n' "$B"
  gen $((2 * 1024 * 1024))
  printf '\r\n'
  for i in $(seq 1 21); do
    printf -- '--%s\r\nContent-Disposition: form-data; name="doc%d[a][b]"; filename=""\r\nContent-Type: application/octet-stream\r\n\r\n\r\n' "$B" "$i"
  done
  printf -- '--%s--\r\n' "$B"
} > "$DIR/upload-then-empty-controls.bin"

# A part with more header lines than Go's parser accepts, after a 2MB upload.
{
  printf -- '--%s\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\n' "$B"
  gen $((2 * 1024 * 1024))
  printf '\r\n--%s\r\nContent-Disposition: form-data; name="x"\r\n' "$B"
  for i in $(seq 0 10100); do printf 'X-P%d: a\r\n' "$i"; done
  printf '\r\nv\r\n--%s--\r\n' "$B"
} > "$DIR/upload-then-header-flood.bin"
