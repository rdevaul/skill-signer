# skill-signer

Sign and verify AI agent skills to establish provenance and trust.

## Description

`skill-signer` provides cryptographic signing for AI agent skills, enabling:

- **Provenance**: Verify who authored a skill
- **Integrity**: Detect tampering with skill files
- **Trust chains**: Verify signed dependencies
- **Revocation**: Invalidate compromised keys

Uses SSH signing (Ed25519) as the primary mechanism, with GPG and Sigstore as alternatives.

## Commands

### sign

Sign a skill directory, generating `MANIFEST.sig.json`:

```bash
skill-signer sign ./my-skill --key ~/.ssh/skill_signing_key
```

### verify

Verify a skill's signature against allowed signers:

```bash
skill-signer verify ./my-skill --allowed-signers ~/.config/skill-signer/allowed_signers
```

### trust

Manage the allowed_signers trust file:

```bash
skill-signer trust add "user@example.com" ~/.ssh/id_ed25519.pub
skill-signer trust revoke "user@example.com" --reason "key compromised"
skill-signer trust list
```

### keygen

Generate a dedicated skill-signing keypair:

```bash
skill-signer keygen --name "My Org Skills" --output ~/.ssh/skill_signing_key
```

## Manifest Format

`MANIFEST.sig.json` structure:

```json
{
  "version": "1.0.0",
  "skill": {
    "name": "example-skill",
    "version": "1.2.3",
    "author": "user@example.com"
  },
  "files": {
    "SKILL.md": {
      "sha256": "abc123...",
      "size": 1234
    },
    "main.py": {
      "sha256": "def456...",
      "size": 5678
    }
  },
  "dependencies": [
    {
      "name": "other-skill",
      "version": ">=1.0.0",
      "signer": "trusted@example.com",
      "manifest_hash": "789abc..."
    }
  ],
  "timestamp": "2026-02-10T16:00:00Z",
  "signer": {
    "identity": "user@example.com",
    "key_fingerprint": "SHA256:...",
    "algorithm": "ssh-ed25519"
  },
  "signature": "-----BEGIN SSH SIGNATURE-----\n..."
}
```

## Trust Model

### allowed_signers Format

Uses SSH's native allowed_signers format:

```
# Format: identity namespaces principals key-type key [options]
user@example.com namespaces="skill-manifest" ssh-ed25519 AAAAC3Nza...
org-skills@company.com namespaces="skill-manifest" ssh-ed25519 AAAAC3Nza... valid-before="20270101"
revoked@example.com namespaces="skill-manifest" ssh-ed25519 AAAAC3Nza... revoked
```

### Trust Hierarchy

1. **Explicit trust**: Key in allowed_signers with valid dates
2. **TOFU (Trust On First Use)**: Optional auto-trust for new skills
3. **Transitive trust**: Verify dependency signatures recursively
4. **Revocation**: Check revoked keys before accepting

## Configuration

`~/.config/skill-signer/config.yaml`:

```yaml
signing:
  method: ssh  # ssh | gpg | sigstore
  key: ~/.ssh/skill_signing_key
  identity: user@example.com

verification:
  allowed_signers: ~/.config/skill-signer/allowed_signers
  tofu: false  # trust on first use
  require_timestamp: true
  max_age_days: 365

revocation:
  check_online: true  # check revocation servers
  cache_hours: 24
```

## Integration with ClawHub

Signed skills on clawhub.com include:

- Publisher verification badge
- Signature validation on install
- Revocation checking
- Trust score based on signer reputation

## Security Considerations

- **Private keys**: Never commit to repositories
- **Key rotation**: Generate new keys periodically
- **Revocation**: Publish revocations promptly when compromised
- **Pinning**: Consider pinning to specific key fingerprints for critical skills
- **Audit trail**: MANIFEST.sig.json provides complete audit history

## Dependencies

- OpenSSH 8.0+ (for ssh-keygen -Y sign/verify)
- Python 3.10+
- Optional: gnupg (for GPG signing)
- Optional: sigstore-python (for Sigstore)

## Related Standards

- [OpenSSF Model Signing (OMS)](https://github.com/ossf/model-signing-spec) — Model signing spec we align with
- [SSH Signing](https://www.agwa.name/blog/post/ssh_signatures) — SSH signature format
- [Sigstore](https://www.sigstore.dev/) — Keyless signing infrastructure

## Examples

### Sign and Publish a Skill

```bash
# Generate signing key (one-time)
skill-signer keygen --name "Dark Matter Lab" --output ~/.ssh/dml_skills

# Sign your skill
skill-signer sign ./my-awesome-skill --key ~/.ssh/dml_skills

# Verify locally before publishing
skill-signer verify ./my-awesome-skill --allowed-signers <(echo "$(cat ~/.ssh/dml_skills.pub)")

# Publish to ClawHub
clawhub publish ./my-awesome-skill
```

### Verify a Downloaded Skill

```bash
# Add publisher to trusted signers
skill-signer trust add "publisher@example.com" https://example.com/keys/skills.pub

# Install and verify
clawhub install example-skill
skill-signer verify ~/.openclaw/skills/example-skill
```

## License

MIT
