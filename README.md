# skill-signer

Cryptographic signing for AI agent skills. Establishes provenance and trust for the agentic ecosystem.

## Why?

AI agent skills are powerful but present a significant attack surface:
- **Supply chain attacks**: Malicious code in dependencies
- **Tampering**: Modified skills after publication
- **Impersonation**: Fake skills claiming to be from trusted sources

`skill-signer` addresses these by enabling cryptographic verification of skill authorship and integrity.

## Quick Start

```bash
# Install
pip install skill-signer

# Generate a signing key
skill-signer keygen --name "Your Name" --output ~/.ssh/skill_signing_key

# Sign a skill
skill-signer sign ./my-skill --key ~/.ssh/skill_signing_key

# Verify a skill
skill-signer verify ./my-skill --allowed-signers allowed_signers
```

## Design Principles

1. **Use existing infrastructure** — SSH keys (Ed25519), not custom crypto
2. **Minimal dependencies** — Core only needs OpenSSH 8.0+
3. **Compatible with OMS** — Aligns with OpenSSF Model Signing spec
4. **Transitive trust** — Verify entire dependency tree
5. **Revocation support** — Handle compromised keys gracefully

## Status

🚧 **Under Development** — Contributions welcome!

See [SKILL.md](./SKILL.md) for the full specification.

## License

MIT

## Authors

- Dark Matter Lab, Relativity Space
- Built with assistance from Jarvis (OpenClaw agent)
