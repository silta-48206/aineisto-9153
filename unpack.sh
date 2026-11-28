#!/bin/bash
# unpack.sh — RUNNER SIDE. Reassemble + decrypt an encrypted-public payload.
#
# Joins the split ciphertext parts, verifies every hash in the manifest,
# decrypts with AES-256-CBC using $RENDER_KEY from the environment (on the
# runner this comes from GitHub Secrets — it is never in the repo), verifies
# the plaintext archive hash, and extracts the payload.
#
# Usage: unpack.sh <payload-dir> <dest-dir>
#   <payload-dir> contains payload.tar.gz.enc.part-* and payload.manifest
#   $RENDER_KEY must be set in the environment.
set -euo pipefail

PAYLOAD_DIR=${1:?usage: unpack.sh <payload-dir> <dest-dir>}
DEST_DIR=${2:?usage: unpack.sh <payload-dir> <dest-dir>}

[ -n "${RENDER_KEY:-}" ] || { echo "ERROR: RENDER_KEY is not set in the environment." >&2; exit 1; }
[ -d "$PAYLOAD_DIR" ] || { echo "ERROR: payload dir not found: $PAYLOAD_DIR" >&2; exit 1; }

MANIFEST="$PAYLOAD_DIR/payload.manifest"
[ -f "$MANIFEST" ] || { echo "ERROR: manifest not found: $MANIFEST" >&2; exit 1; }

get_field() { grep -E "^$1=" "$MANIFEST" | head -1 | cut -d= -f2-; }
ARCHIVE_FILE=$(get_field archive_file)
ARCHIVE_SHA=$(get_field archive_sha256)
ENC_FILE=$(get_field encrypted_file)
ENC_SHA=$(get_field encrypted_sha256)
PART_COUNT=$(get_field part_count)

echo "== verify parts against manifest"
FOUND=$(ls "$PAYLOAD_DIR/$ENC_FILE".part-* 2>/dev/null | wc -l)
[ "$FOUND" -eq "$PART_COUNT" ] || { echo "ERROR: expected $PART_COUNT parts, found $FOUND" >&2; exit 1; }
while read -r name sha _size; do
  [ -n "${name:-}" ] || continue
  actual=$(sha256sum "$PAYLOAD_DIR/$name" | awk '{print $1}')
  [ "$actual" = "${sha#sha256=}" ] || { echo "ERROR: part hash mismatch: $name" >&2; exit 1; }
done < <(grep -E '\.part-[0-9]+ ' "$MANIFEST")
echo "all $PART_COUNT parts hash-verified"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "== join parts"
cat "$PAYLOAD_DIR/$ENC_FILE".part-* > "$TMP/$ENC_FILE"
actual=$(sha256sum "$TMP/$ENC_FILE" | awk '{print $1}')
[ "$actual" = "$ENC_SHA" ] || { echo "ERROR: joined ciphertext hash mismatch" >&2; exit 1; }

echo "== decrypt AES-256-CBC (password from \$RENDER_KEY env only)"
if ! openssl enc -d -aes-256-cbc -salt -pbkdf2 -iter 200000 \
  -in "$TMP/$ENC_FILE" -out "$TMP/$ARCHIVE_FILE" -pass env:RENDER_KEY; then
  echo "ERROR: decryption failed (wrong password or corrupted ciphertext)" >&2
  exit 1
fi
actual=$(sha256sum "$TMP/$ARCHIVE_FILE" | awk '{print $1}')
[ "$actual" = "$ARCHIVE_SHA" ] || { echo "ERROR: decrypted archive hash mismatch (wrong password or corruption)" >&2; exit 1; }

echo "== extract"
mkdir -p "$DEST_DIR"
tar --no-same-owner -xzf "$TMP/$ARCHIVE_FILE" -C "$DEST_DIR"
echo "DONE: payload extracted to $DEST_DIR"
