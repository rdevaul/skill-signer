# skill-signer

![Tests](https://github.com/rdevaul/skill-signer/actions/workflows/publish.yml/badge.svg)

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

# Sign a skill: writes MANIFEST.json and MANIFEST.json.sig
skill-signer sign ./my-skill --key ~/.ssh/skill_signing_key \
    --description "What this skill does, in a sentence or two."

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
skill-signer sign <skill_dir> --key <path> [--name <name>] [--version <ver>]
    [--description <text>] [--script <path>]... [--network none|loopback|full]
    [--secret <name>]... [--read-only <path>]...
```

Writes a **version 2 manifest**: two files at the top of the skill directory.

| File | Content |
|---|---|
| `MANIFEST.json` | The manifest |
| `MANIFEST.json.sig` | An OpenSSH signature over the exact bytes of `MANIFEST.json`, namespace `skill-manifest` |

```json
{
  "manifest_version": 2,
  "name": "my-skill",
  "version": "1.4.0",
  "description": "What this skill does, in a sentence or two.",
  "files": {
    "SKILL.md": {"sha256": "…", "size": 4180},
    "scripts/export.py": {"sha256": "…", "size": 912}
  },
  "scripts": ["scripts/export.py"],
  "requires": {"network": "none", "secrets": [], "read_only": []}
}
```

- **Every file is listed.** Dotfiles, `__pycache__`, `node_modules`: whatever is in the directory is signed, and `verify` fails on any file that is not listed. `sign` warns about files that look like clutter; remove them and sign again.
- **Symbolic links are refused**, along with anything else that is not a regular file or a directory.
- **The signer is not in the manifest.** Whoever verifies finds the signer in their own `allowed_signers` file, by the key that made the signature. `sign` needs no `--identity`.
- **`scripts`** are the files the skill may ask an agent to run; a skill with none is instruction-only. **`requires`** says what those scripts need from a sandboxed shell. A loader such as xshell uses both to decide where the skill may be used.
- The skill's identity is the SHA-256 of `MANIFEST.json`, which `sign` prints.
- Limits: 512 files, 64 MiB in total, paths of at most 255 bytes, and no two paths that differ only by letter case.

`--name` defaults to the directory's name and must be 1–64 characters of `a-z`, `0-9`, `-` and `_`, starting with a letter. `--description` is required the first time (at most 500 characters). A value you do not give is kept from the existing `MANIFEST.json`, then read from `name:`, `version:` and `description:` lines in `SKILL.md` front matter, so signing again after an edit needs only `--key`.

Because the signature is over the stored file, stock OpenSSH can check a skill with no other tool:

```bash
ssh-keygen -Y verify -f allowed_signers -I user@example.com \
    -n skill-manifest -s MANIFEST.json.sig < MANIFEST.json
```

(That checks the manifest only. `skill-signer verify` also checks every file against it.)

#### Version 1 manifests

`sign --manifest-version 1` writes the older single file, `MANIFEST.sig.json`, and is the only form that supports GPG keys and `publish` today. It takes `--identity` (or reads it from the key's `.meta` sidecar) and records it, lowercased, in the manifest. Version 1 skips dotfiles, `__pycache__` and `node_modules`, follows symbolic links, and takes the signer's identity from the manifest being checked, so prefer version 2 for anything a program will load.

### `resign` — move a skill from version 1 to version 2

```
skill-signer resign <skill_dir> --key <path> [--allowed-signers <path>] [--skip-check]
    [--description <text>] [...the same fields as sign]
```

Verifies the version 1 manifest (signature and file hashes), then writes version 2 and removes `MANIFEST.sig.json`. If the old manifest does not verify, nothing is changed; `--skip-check` signs the files as they are now. The version is carried over; files version 1 left out (dotfiles, for example) are now listed.

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

For a version 2 skill this checks, in order: the signature over `MANIFEST.json` by a key in `allowed_signers` that is trusted for the `skill-manifest` namespace; that the manifest is well formed (no unknown fields, no duplicate keys); and that the directory holds exactly the listed files with the listed sizes and hashes, and no links. It prints the signer it found for the key.

A directory with only `MANIFEST.sig.json` is checked as version 1, with a note. There, identity matching is case-insensitive (normalized at our layer; SSH itself is case-sensitive).

### `inspect` — inspect a manifest without verifying

```
skill-signer inspect <skill_dir> [--verbose]
```

### `publish` — publish a signed skill (stub)

```
skill-signer publish <skill_dir> [--allowed-signers <path>]
```

Takes a version 1 manifest; the registry does not accept version 2 yet. Verifies the skill is signed and ready for publication. Shows what would be published to a registry. Full registry integration coming soon.

## Configuration

skill-signer supports optional configuration via `~/.config/skill-signer/config.yaml`:

```yaml
signing:
  key: ~/.ssh/skill-signing-key
  identity: your-email@example.com

verification:
  allowed_signers: ~/.config/skill-signer/allowed_signers
  tofu: false
```

When configured, you can sign skills without specifying `--key` and `--identity` every time:

```bash
skill-signer sign ./my-skill
```

Configuration requires PyYAML: `pip install pyyaml` or `pip install skill-signer[config]`

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

## Comparison with Other Solutions

| Feature | skill-signer | ClawHub | Sundial |
|---------|--------------|---------|---------|
| **Verification Method** | SSH Ed25519 cryptographic signatures | SHA-256 hash verification | Automated scanning (no crypto) |
| **Publisher Identity** | Persistent key-based identity | No persistent identity | No cryptographic identity |
| **Tamper Detection** | Cryptographic signature + file hashes | File hashes only | Pattern-based scanning |
| **Revocation** | Built-in key revocation | N/A | N/A |
| **Use Case** | Provenance & trust for skills | Skill distribution | Security scanning |

**skill-signer vs ClawHub**: ClawHub uses SHA-256 hash verification to detect file tampering, but has no mechanism for persistent publisher identity. skill-signer uses SSH Ed25519 key-based provenance — the same model as git commit signing — to establish who published a skill and verify both authorship and integrity.

**skill-signer vs Sundial**: Sundial provides automated security scanning for skills but does not use cryptographic signing. skill-signer complements security scanning with cryptographic provenance, enabling trust chains and accountability.

## Status

🟡 **Beta** — Core signing and verification complete. Registry integration in progress.

Production-ready for signing and verification workflows.

## Roadmap

- **v0.2** — Registry submission protocol (skill publishing to central/federated registries)
- **v0.3** — TOFU (Trust On First Use) mode for automatic key acceptance
- **v0.4** — Sigstore integration for transparency log

See [SKILL.md](./SKILL.md) for the full specification.

## License

MIT

## Authors

- Dark Matter Lab, Relativity Space
- Built with assistance from Jarvis (OpenClaw agent)
