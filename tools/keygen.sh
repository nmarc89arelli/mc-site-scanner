#!/usr/bin/env bash
# One-time: create the Ed25519 signing key for Relish Security releases.
# The private key never leaves this machine. Back it up to your password manager.
set -euo pipefail
KEY="${HOME}/.mcss/release-key.pem"
if ! openssl genpkey -algorithm ed25519 -out /dev/null 2>/dev/null; then
  echo "Your openssl cannot make Ed25519 keys. Run: brew install openssl  and then:  export PATH=\"\$(brew --prefix openssl)/bin:\$PATH\"" >&2; exit 1
fi
if [ -f "$KEY" ]; then echo "Key already exists at $KEY. Not overwriting." >&2; exit 1; fi
mkdir -p "$(dirname "$KEY")"; chmod 700 "$(dirname "$KEY")"
openssl genpkey -algorithm ed25519 -out "$KEY"; chmod 600 "$KEY"
PUB=$(openssl pkey -in "$KEY" -pubout -outform DER | tail -c 32 | base64)
echo "$PUB" > "${HOME}/.mcss/public-key.txt"
echo
echo "Private key saved to $KEY  (back this file up; without it you cannot sign releases)"
echo "Public key (goes into the plugin, the release script does this for you):"
echo "  $PUB"
