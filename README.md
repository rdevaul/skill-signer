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

# Generate a signing key (--name sets your identity; a .meta sidecar is also written)
skill-signer keygen --name "user@example.com" --output ~/.ssh/skill_signing_key

# Sign a skill (identity is auto-discovered from the .meta sidecar)
skill-signer sign ./my-skill --key ~/.ssh/skill_signing_key

# Add the key to trusted signers (identity read from the key comment automatically)
skill-signer trust add ~/.ssh/skill_signing_key.pub

# Verify a skill
skill-signer verify ./my-skill --allowed-signers allowed_signers
```

## Commands

### `keygen` — generate a signing keypair

```
skill-signer keygen --output <path> [--name <identity>]
```

| Flag | Description |
|------|-------------|
| `--output` | **(required)** Path to write the private key |
| `--name` | Identity / key comment (e.g. `user@example.com`). Defaults to `skill-signing-key`. |
| `--comment` | Hidden alias for `--name` (backward compatibility) |

After key generation, two extra files are created alongside the private key:

- `<output>.pub` — SSH public key (share this to let others verify your signatures)
- `<output>.meta` — JSON sidecar with `{"identity": "…", "created": "…"}` so other commands can auto-discover your identity without you having to re-type it every time.

### `sign` — sign a skill directory

```
skill-signer sign <skill_dir> --key <path> [--identity <identity>] [--version <ver>]
```

If `--identity` is omitted, `sign` looks for a `.meta` sidecar at `<key>.meta` (written by `keygen`) and reads the identity from it. If neither is available, it exits with a helpful error.

Identities are **normalized to lowercase** before signing to avoid case-sensitivity issues between platforms.

### `trust add` — register a trusted signer

```
skill-signer trust add [<identity>] <pubkey>
skill-signer trust add <pubkey>            # identity auto-read from key comment
```

`identity` is now **optional**. When omitted, the identity is parsed from the SSH public key's comment field (the last token(s) on the pubkey line). If the key has no comment and no identity is supplied, the command exits with an error.

Identities are normalized to lowercase for consistent matching.

### `trust revoke` — revoke a trusted signer

```
skill-signer trust revoke <identity>
```

### `trust list` — list trusted signers

```
skill-signer trust list
```

### `verify` — verify a signed skill

```
skill-signer verify <skill_dir> [--allowed-signers <path>]
```

Identity matching is case-insensitive (normalized at our layer; SSH itself is case-sensitive).

### `inspect` — inspect a manifest without verifying

```
skill-signer inspect <skill_dir> [--verbose]
```

## Identity & Case Normalization

All commands that store or compare identities (sign, verify, trust add) normalize them to
**lowercase** before use. This means `User@Example.COM` and `user@example.com` are treated as the
same identity. The normalization happens at the `skill-signer` layer because the underlying
`ssh-keygen -Y verify` tool performs case-sensitive comparisons.

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
