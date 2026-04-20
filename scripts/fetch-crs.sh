#!/usr/bin/env bash
# Fetch and verify the OWASP CRS rule tarball, then place rules and
# crs-setup.conf into internal/protections/crs/ where embed.go picks
# them up.
#
# Version is pinned in versions.mk; checksum is pinned in rules/CRS_SHA256.
# Bumping CRS means editing both and nothing else.

set -euo pipefail

cd "$(dirname "$0")/.."

# shellcheck disable=SC1091
source versions.mk

TARBALL="/tmp/crs-${CRS_VERSION}.tar.gz"
EXTRACT_DIR="/tmp/crs-${CRS_VERSION}-extract"
TARGET_PKG="internal/protections/crs"
TARGET_RULES="${TARGET_PKG}/rules"
TARGET_FTW_TESTS="tests/ftw/crs-tests"

echo "==> Downloading CRS ${CRS_VERSION}"
curl -fsSL -o "${TARBALL}" \
  "https://github.com/coreruleset/coreruleset/archive/refs/tags/${CRS_VERSION}.tar.gz"

echo "==> Verifying checksum against rules/CRS_SHA256"
EXPECTED=$(awk '{print $1}' rules/CRS_SHA256)
# sha256sum (Linux/Alpine) and shasum -a 256 (macOS) produce the same output format
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "${TARBALL}" | awk '{print $1}')
else
  ACTUAL=$(shasum -a 256 "${TARBALL}" | awk '{print $1}')
fi
if [ "${EXPECTED}" != "${ACTUAL}" ]; then
  echo "checksum mismatch: expected ${EXPECTED}, got ${ACTUAL}" >&2
  exit 1
fi

echo "==> Extracting into ${EXTRACT_DIR}"
rm -rf "${EXTRACT_DIR}"
mkdir -p "${EXTRACT_DIR}"
tar -xzf "${TARBALL}" -C "${EXTRACT_DIR}" --strip-components=1

echo "==> Installing into ${TARGET_PKG}"
rm -rf "${TARGET_RULES}"
mkdir -p "${TARGET_RULES}"
cp "${EXTRACT_DIR}/rules/"*.conf "${TARGET_RULES}/"
cp "${EXTRACT_DIR}/rules/"*.data "${TARGET_RULES}/" 2>/dev/null || true
cp "${EXTRACT_DIR}/crs-setup.conf.example" "${TARGET_PKG}/crs-setup.conf"

# Also place rules under rules/ so local developers see them (gitignored).
rm -f rules/*.conf rules/*.data
cp "${EXTRACT_DIR}/rules/"*.conf rules/
cp "${EXTRACT_DIR}/rules/"*.data rules/ 2>/dev/null || true

# Install the FTW regression test corpus for the nightly security workflow.
# Gitignored; consumed by tests/ftw/runner_test.go via make test-ftw.
if [ -d "${EXTRACT_DIR}/tests/regression/tests" ]; then
  rm -rf "${TARGET_FTW_TESTS}"
  mkdir -p "${TARGET_FTW_TESTS}"
  cp -R "${EXTRACT_DIR}/tests/regression/tests/." "${TARGET_FTW_TESTS}/"
  echo "==> Installed FTW test corpus into ${TARGET_FTW_TESTS}"
fi

echo "==> Done. $(ls "${TARGET_RULES}" | wc -l | tr -d ' ') rule files installed."
