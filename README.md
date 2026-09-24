# Relish Security

WordPress malware and integrity scanner with incident response tools, built for Marcarelli Consulting client sites.

Releases are signed. Sites only install a release or a rules file whose Ed25519 signature verifies against the public key built into the plugin.

## Releasing

    tools/release.sh 1.6.0 "What changed"      # plugin release
    tools/release.sh rules "New detections"     # rules only

First time on a new machine: `tools/keygen.sh`, then copy the private key from your password manager if this is not the machine that generated it.
