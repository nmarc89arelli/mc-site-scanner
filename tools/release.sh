#!/usr/bin/env bash
# Usage:  tools/release.sh 1.6.0 "What changed"        release a new plugin version
#         tools/release.sh rules "Added X detection"    publish updated rules.dat only
# Run from the repo root. Needs: git, gh (logged in), openssl with Ed25519, zip.
set -euo pipefail
cd "$(dirname "$0")/.."
KEY="${HOME}/.mcss/release-key.pem"; PUB="${HOME}/.mcss/public-key.txt"
[ -f "$KEY" ] || { echo "No signing key. Run tools/keygen.sh first." >&2; exit 1; }
command -v gh >/dev/null || { echo "Install the GitHub CLI: brew install gh && gh auth login" >&2; exit 1; }
SIGN() { openssl pkeyutl -sign -inkey "$KEY" -rawin -in "$1" -out "$1.sig"; }
VERIFY() { openssl pkeyutl -verify -pubin -inkey <(openssl pkey -in "$KEY" -pubout) -rawin -in "$1" -sigfile "$1.sig" >/dev/null; }
REPO=$(git remote get-url origin | sed -E 's#.*github.com[:/]##; s#\.git$##')
PUBKEY=$(cat "$PUB")
WHAT="${1:-}"; NOTE="${2:-}"
[ -n "$WHAT" ] || { echo "Usage: tools/release.sh <version|rules> \"note\"" >&2; exit 1; }

# Always: sign rules.dat
[ -f mc-site-scanner/rules.dat ] || { echo "mc-site-scanner/rules.dat missing" >&2; exit 1; }
cp mc-site-scanner/rules.dat rules.dat
SIGN rules.dat && VERIFY rules.dat

if [ "$WHAT" = "rules" ]; then
  git add rules.dat rules.dat.sig mc-site-scanner/rules.dat
  git commit -m "Rules: ${NOTE:-update}" >/dev/null
  git push
  echo "Rules published. Sites pick them up within a day, or press Check now in Settings."
  exit 0
fi

VER="$WHAT"
echo "$VER" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "Version must look like 1.6.0" >&2; exit 1; }
# Bake the public key and version into the plugin
sed -i '' -e "s#define( 'MCSS_PUBKEY', '[^']*' );#define( 'MCSS_PUBKEY', '${PUBKEY}' );#" mc-site-scanner/mc-site-scanner.php
sed -i '' -e "s#^ \* Version: .*# * Version: ${VER}#" -e "s#const VERSION      = '[^']*';#const VERSION      = '${VER}';#" mc-site-scanner/mc-site-scanner.php
grep -q "MCSS_PUBKEY', '${PUBKEY}'" mc-site-scanner/mc-site-scanner.php || { echo "Public key was not written into the plugin" >&2; exit 1; }
php -l mc-site-scanner/mc-site-scanner.php >/dev/null 2>&1 || true

rm -f mc-site-scanner.zip mc-site-scanner.zip.sig
zip -rq mc-site-scanner.zip mc-site-scanner -x '*.DS_Store' -x '*.tmp'
SIGN mc-site-scanner.zip && VERIFY mc-site-scanner.zip

cat > manifest.json <<JSON
{
  "version": "${VER}",
  "download_url": "https://github.com/${REPO}/releases/download/v${VER}/mc-site-scanner.zip",
  "requires": "5.8",
  "requires_php": "7.4",
  "tested": "7.1",
  "released": "$(date -u +%Y-%m-%d)",
  "changelog": $(printf '%s' "${NOTE:-Release $VER}" | python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))')
}
JSON
SIGN manifest.json && VERIFY manifest.json

git add -A
git commit -m "Release ${VER}: ${NOTE:-}" >/dev/null
git tag -a "v${VER}" -m "v${VER}"
git push && git push --tags
gh release create "v${VER}" mc-site-scanner.zip mc-site-scanner.zip.sig --title "v${VER}" --notes "${NOTE:-Release $VER}"
echo
echo "Released v${VER}. Sites see it within 12 hours, or press Check now in Settings > Updates."
