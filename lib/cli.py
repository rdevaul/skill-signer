#!/usr/bin/env python3
"""
CLI for skill-signer: cryptographic signing for AI agent skills.
"""

import os
import sys
import argparse
import json
import datetime
from pathlib import Path
from typing import Optional

from . import (
    create_manifest,
    sign_manifest,
    save_manifest,
    load_manifest,
    generate_keypair,
    verify_data,
    check_ssh_version,
)
from .trust import add_signer, revoke_signer, list_signers, fetch_pubkey
from .config import load_config


DEFAULT_CONFIG_DIR = os.path.expanduser("~/.config/skill-signer")
DEFAULT_ALLOWED_SIGNERS = os.path.join(DEFAULT_CONFIG_DIR, "allowed_signers")


def ensure_config_dir():
    """Ensure the config directory exists."""
    os.makedirs(DEFAULT_CONFIG_DIR, exist_ok=True)


def cmd_sign(args):
    """Sign a skill directory."""
    skill_dir = Path(args.skill_dir).resolve()
    if not skill_dir.is_dir():
        print(f"Error: Not a directory: {skill_dir}", file=sys.stderr)
        return 1

    # Load config for defaults
    config = load_config()

    # Determine key path: from --key flag or from config
    key_path = args.key
    if not key_path:
        key_path = config.signing_key
        if key_path:
            print(f"Using key from config: {key_path}")

    if not key_path:
        print(f"Error: --key is required (or set signing.key in ~/.config/skill-signer/config.yaml)", file=sys.stderr)
        return 1

    key_path = os.path.expanduser(key_path)
    if not os.path.exists(key_path):
        print(f"Error: Key not found: {key_path}", file=sys.stderr)
        return 1

    # Determine identity: from --identity flag, config, or .meta sidecar file
    identity = args.identity
    if not identity:
        identity = config.signing_identity
        if identity:
            print(f"Using identity from config: {identity}")

    if not identity:
        meta_path = f"{key_path}.meta"
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r") as f:
                    meta = json.load(f)
                identity = meta.get("identity")
            except Exception as e:
                print(
                    f"Warning: Could not read meta file {meta_path}: {e}",
                    file=sys.stderr,
                )

    if not identity:
        print(
            f"Error: --identity is required (or generate a key with 'skill-signer keygen --name' "
            f"which creates a .meta sidecar at <key>.meta)",
            file=sys.stderr,
        )
        return 1

    # Normalize identity to lowercase for case-insensitive matching.
    # SSH allowed_signers matching is case-sensitive at the OS level, so we
    # normalize at our layer to avoid subtle mismatches.
    identity = identity.lower()

    # Report when identity was auto-discovered from the meta sidecar
    if not args.identity:
        print(f"Using identity from {key_path}.meta: {identity}")

    try:
        # Create manifest
        print(f"Creating manifest for {skill_dir.name}...")
        manifest = create_manifest(
            str(skill_dir),
            author=identity,
            version=args.version
        )

        print(f"Found {len(manifest.files)} files")

        # Determine key type from --key-type flag or auto-detect
        key_type = getattr(args, 'key_type', None)

        # Sign manifest
        print(f"Signing with key {key_path}...")
        signed_manifest = sign_manifest(manifest, key_path, identity, key_type=key_type)

        # Save manifest
        output_path = save_manifest(signed_manifest, str(skill_dir))
        print(f"Saved signed manifest: {output_path}")

        # Show fingerprint
        if signed_manifest.signer:
            print(f"Signature: {signed_manifest.signer.key_fingerprint}")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_verify(args):
    """Verify a signed skill directory."""
    skill_dir = Path(args.skill_dir).resolve()
    manifest_path = skill_dir / "MANIFEST.sig.json"

    if not manifest_path.exists():
        print(f"Error: No manifest found: {manifest_path}", file=sys.stderr)
        return 1

    # Load config for defaults
    config = load_config()

    # Determine allowed_signers path: from --allowed-signers flag or from config
    allowed_signers = args.allowed_signers
    if not allowed_signers:
        allowed_signers = config.verification_allowed_signers or DEFAULT_ALLOWED_SIGNERS

    if not os.path.exists(allowed_signers):
        print(f"Error: allowed_signers not found: {allowed_signers}", file=sys.stderr)
        print(f"Hint: Use 'skill-signer trust add' to add trusted signers")
        return 1

    try:
        # Load manifest
        print(f"Loading manifest from {manifest_path}...")
        manifest = load_manifest(str(manifest_path))

        if not manifest.signature or not manifest.signer:
            print("Error: Manifest is not signed", file=sys.stderr)
            return 1

        print(f"Skill: {manifest.skill_name} v{manifest.skill_version}")
        print(f"Author: {manifest.author}")
        print(f"Signer: {manifest.signer.identity}")
        print(f"Key: {manifest.signer.key_fingerprint}")

        # Verify signature
        print("Verifying signature...")
        payload = manifest.signing_payload()

        # Normalize identity to lowercase for case-insensitive matching.
        # SSH allowed_signers matching is case-sensitive at the OS level, so we
        # normalize at our layer to avoid subtle mismatches.
        identity = manifest.signer.identity.lower()

        result = verify_data(
            payload,
            manifest.signature,
            allowed_signers,
            identity
        )

        if result.valid:
            print("✓ Signature is valid")

            # Verify file hashes
            print(f"Verifying file hashes for {len(manifest.files)} files...")

            from .manifest import hash_file

            missing_files = []
            modified_files = []

            for file_path, expected_entry in manifest.files.items():
                full_path = skill_dir / file_path

                if not full_path.exists():
                    missing_files.append(file_path)
                    continue

                # Compute current hash
                try:
                    current_entry = hash_file(full_path)

                    if current_entry.sha256 != expected_entry.sha256:
                        modified_files.append(file_path)
                except Exception as e:
                    print(f"✗ Error reading {file_path}: {e}", file=sys.stderr)
                    return 1

            # Report any issues
            if missing_files or modified_files:
                print(f"✗ File verification failed:", file=sys.stderr)

                if missing_files:
                    print(f"\nMissing files ({len(missing_files)}):", file=sys.stderr)
                    for path in missing_files:
                        print(f"  - {path}", file=sys.stderr)

                if modified_files:
                    print(f"\nModified files ({len(modified_files)}):", file=sys.stderr)
                    for path in modified_files:
                        print(f"  - {path}", file=sys.stderr)

                return 1

            print(f"✓ All {len(manifest.files)} files verified")
            return 0
        else:
            print(f"✗ Signature verification failed: {result.error}")
            return 1

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_keygen(args):
    """Generate a new SSH or GPG keypair."""
    key_type = args.type or "ssh"

    if key_type == "gpg":
        # GPG key generation
        from . import gpg_signer

        # Check if GPG is available
        ok, msg = gpg_signer.check_gpg_available()
        if not ok:
            print(f"Error: {msg}", file=sys.stderr)
            return 1

        # Get name and email
        name = args.name or args.comment
        email = args.email

        if not name:
            print("Error: --name is required for GPG key generation", file=sys.stderr)
            return 1

        if not email:
            print("Error: --email is required for GPG key generation", file=sys.stderr)
            return 1

        # Generate GPG key
        output_dir = args.output if args.output else None
        success, message = gpg_signer.generate_keypair(name, email, output_dir)

        if success:
            print(f"✓ {message}")

            # Get key ID
            key_id = gpg_signer.get_gpg_key_fingerprint(email)

            # Offer to create initial config file
            from .config import DEFAULT_CONFIG_PATH, save_config

            if not os.path.exists(DEFAULT_CONFIG_PATH):
                print(f"\nWould you like to create a config file at {DEFAULT_CONFIG_PATH}?")
                print(f"This will set default key and identity for signing. (y/n): ", end='', flush=True)

                try:
                    response = input().strip().lower()
                    if response in ['y', 'yes']:
                        config_data = {
                            "signing": {
                                "key": key_id,
                                "identity": email,
                            },
                            "verification": {
                                "allowed_signers": DEFAULT_ALLOWED_SIGNERS,
                                "tofu": False,
                            },
                            "registry": {
                                "url": "http://54.219.240.149:8400",
                                "auto_register": True,
                            },
                        }

                        if save_config(config_data):
                            print(f"✓ Config saved to {DEFAULT_CONFIG_PATH}")
                            print(f"\nYou can now sign skills without --key and --identity flags:")
                            print(f"skill-signer sign <skill-directory>")
                        else:
                            print(f"\nTo enable config support, install PyYAML:")
                            print(f"pip install pyyaml")
                except (EOFError, KeyboardInterrupt):
                    print()  # Just newline, skip config creation

            return 0
        else:
            print(f"Error: {message}", file=sys.stderr)
            return 1

    else:  # SSH key generation
        if not args.output:
            print("Error: --output is required for SSH key generation", file=sys.stderr)
            return 1

        output_path = os.path.expanduser(args.output)

        # --name is the primary flag; --comment is a hidden backward-compat alias
        name = args.name or args.comment or "skill-signing-key"

        success, message = generate_keypair(output_path, name)

        if success:
            print(f"✓ {message}")
            print(f"Private key: {output_path}")
            print(f"Public key:  {output_path}.pub")

            # Write metadata sidecar so 'sign' can auto-discover identity
            meta_path = f"{output_path}.meta"
            meta = {
                "identity": name,
                "created": datetime.datetime.utcnow().isoformat() + "Z",
                "key_type": "ssh",
            }
            with open(meta_path, "w") as f:
                json.dump(meta, f, indent=2)
            print(f"Meta file:   {meta_path}")

            # Show how to add to trusted signers (no identity required now)
            print(f"\nTo trust this key:")
            print(f"skill-signer trust add {output_path}.pub")

            # Offer to create initial config file
            from .config import DEFAULT_CONFIG_PATH, save_config

            if not os.path.exists(DEFAULT_CONFIG_PATH):
                print(f"\nWould you like to create a config file at {DEFAULT_CONFIG_PATH}?")
                print(f"This will set default key and identity for signing. (y/n): ", end='', flush=True)

                try:
                    response = input().strip().lower()
                    if response in ['y', 'yes']:
                        config_data = {
                            "signing": {
                                "key": output_path,
                                "identity": name,
                            },
                            "verification": {
                                "allowed_signers": DEFAULT_ALLOWED_SIGNERS,
                                "tofu": False,
                            },
                            "registry": {
                                "url": "http://54.219.240.149:8400",
                                "auto_register": True,
                            },
                        }

                        if save_config(config_data):
                            print(f"✓ Config saved to {DEFAULT_CONFIG_PATH}")
                            print(f"\nYou can now sign skills without --key and --identity flags:")
                            print(f"skill-signer sign <skill-directory>")
                        else:
                            print(f"\nTo enable config support, install PyYAML:")
                            print(f"pip install pyyaml")
                except (EOFError, KeyboardInterrupt):
                    print()  # Just newline, skip config creation

            return 0
        else:
            print(f"Error: {message}", file=sys.stderr)
            return 1


def cmd_trust_add(args):
    """Add a trusted signer."""
    ensure_config_dir()
    allowed_signers = args.allowed_signers or DEFAULT_ALLOWED_SIGNERS

    # Accept either:  trust add <pubkey>
    #             or: trust add <identity> <pubkey>
    positionals = args.positionals
    if len(positionals) == 1:
        identity_arg = None
        pubkey_arg = positionals[0]
    elif len(positionals) == 2:
        identity_arg = positionals[0]
        pubkey_arg = positionals[1]
    else:
        print(
            f"Error: Expected '[identity] pubkey', got {len(positionals)} arguments",
            file=sys.stderr,
        )
        return 1

    try:
        # Handle URL vs file path
        if pubkey_arg.startswith(('http://', 'https://')):
            print(f"Fetching public key from {pubkey_arg}...")
            pubkey_content = fetch_pubkey(pubkey_arg)
        else:
            pubkey_path = os.path.expanduser(pubkey_arg)
            if not os.path.exists(pubkey_path):
                print(f"Error: Public key not found: {pubkey_path}", file=sys.stderr)
                return 1

            with open(pubkey_path, 'r') as f:
                pubkey_content = f.read().strip()

        # If identity was not explicitly given, parse it from the pubkey comment.
        # SSH pubkey format: <algorithm> <key_material> [comment]
        # The comment is everything after the key material (third token onward).
        if identity_arg is None:
            parts = pubkey_content.split()
            if len(parts) >= 3:
                identity_arg = " ".join(parts[2:])

            if not identity_arg:
                print(
                    "Error: No identity provided and the public key has no comment field.\n"
                    "Please supply one explicitly: skill-signer trust add <identity> <pubkey>",
                    file=sys.stderr,
                )
                return 1

            print(f"Using identity from key comment: {identity_arg}")

        # Normalize identity to lowercase for case-insensitive matching.
        # SSH allowed_signers matching is case-sensitive at the OS level, so we
        # normalize at our layer to avoid subtle mismatches.
        identity_arg = identity_arg.lower()

        print(f"Adding signer {identity_arg}...")
        add_signer(identity_arg, pubkey_content, allowed_signers)

        print(f"✓ Added {identity_arg} to {allowed_signers}")
        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_trust_revoke(args):
    """Revoke a trusted signer."""
    allowed_signers = args.allowed_signers or DEFAULT_ALLOWED_SIGNERS

    if not os.path.exists(allowed_signers):
        print(f"Error: allowed_signers not found: {allowed_signers}", file=sys.stderr)
        return 1

    try:
        print(f"Revoking signer {args.identity}...")
        revoke_signer(args.identity, allowed_signers)
        print(f"✓ Revoked {args.identity} in {allowed_signers}")
        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_trust_list(args):
    """List trusted signers."""
    allowed_signers = args.allowed_signers or DEFAULT_ALLOWED_SIGNERS

    if not os.path.exists(allowed_signers):
        print(f"No allowed_signers file found: {allowed_signers}")
        print(f"Use 'skill-signer trust add' to add trusted signers")
        return 0

    try:
        signers = list_signers(allowed_signers)

        if not signers:
            print("No signers found")
            return 0

        print(f"Trusted signers ({len(signers)}):")
        for signer in signers:
            status = "REVOKED" if signer.get('revoked') else "active"
            print(f"  {signer['identity']} [{status}]")
            print(f"    {signer['algorithm']} {signer['key'][:60]}...")
            if signer.get('namespaces'):
                print(f"    namespaces: {signer['namespaces']}")
            print()

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_publish(args):
    """Publish a signed skill to a registry."""
    import tarfile
    import tempfile
    import requests

    skill_dir = Path(args.skill_dir).resolve()
    manifest_path = skill_dir / "MANIFEST.sig.json"

    if not manifest_path.exists():
        print(f"Error: No manifest found: {manifest_path}", file=sys.stderr)
        print(f"Hint: Sign the skill first with 'skill-signer sign'", file=sys.stderr)
        return 1

    # Load config for defaults
    config = load_config()

    # Determine registry URL
    registry_url = args.registry
    if not registry_url:
        registry_url = config.registry_url or os.environ.get('SKILL_REGISTRY_URL')

    if not registry_url:
        print("Error: No registry URL specified", file=sys.stderr)
        print("Set via --registry flag, SKILL_REGISTRY_URL env var, or config file", file=sys.stderr)
        return 1

    # Remove trailing slash
    registry_url = registry_url.rstrip('/')

    # Determine allowed_signers path for verification (SSH only)
    allowed_signers = args.allowed_signers
    if not allowed_signers:
        allowed_signers = config.verification_allowed_signers or DEFAULT_ALLOWED_SIGNERS

    try:
        # Load and verify the manifest
        print(f"Loading manifest from {manifest_path}...")
        manifest = load_manifest(str(manifest_path))

        if not manifest.signature or not manifest.signer:
            print("Error: Manifest is not signed", file=sys.stderr)
            return 1

        print(f"Skill: {manifest.skill_name} v{manifest.skill_version}")
        print(f"Author: {manifest.author}")
        print(f"Signer: {manifest.signer.identity}")

        # Verify signature
        print("Verifying signature...")
        from .manifest import verify_manifest
        identity = manifest.signer.identity.lower()

        # For SSH, we need allowed_signers; for GPG, it's optional
        key_type = getattr(manifest.signer, 'key_type', 'ssh')
        if key_type == 'ssh' and not os.path.exists(allowed_signers):
            print(f"Warning: allowed_signers not found: {allowed_signers}", file=sys.stderr)
            print(f"Skipping signature verification for SSH key", file=sys.stderr)
            result = None
        else:
            result = verify_manifest(manifest, allowed_signers, identity)

        if result and not result.valid:
            print(f"✗ Signature verification failed: {result.error}", file=sys.stderr)
            return 1

        if result and result.valid:
            print("✓ Signature is valid")

        # Verify file hashes
        print(f"Verifying file hashes for {len(manifest.files)} files...")

        from .manifest import hash_file

        missing_files = []
        modified_files = []

        for file_path, expected_entry in manifest.files.items():
            full_path = skill_dir / file_path

            if not full_path.exists():
                missing_files.append(file_path)
                continue

            try:
                current_entry = hash_file(full_path)
                if current_entry.sha256 != expected_entry.sha256:
                    modified_files.append(file_path)
            except Exception as e:
                print(f"✗ Error reading {file_path}: {e}", file=sys.stderr)
                return 1

        if missing_files or modified_files:
            print(f"✗ File verification failed:", file=sys.stderr)

            if missing_files:
                print(f"\nMissing files ({len(missing_files)}):", file=sys.stderr)
                for path in missing_files:
                    print(f"  - {path}", file=sys.stderr)

            if modified_files:
                print(f"\nModified files ({len(modified_files)}):", file=sys.stderr)
                for path in modified_files:
                    print(f"  - {path}", file=sys.stderr)

            return 1

        print(f"✓ All {len(manifest.files)} files verified")

        # Dry run mode
        if args.dry_run:
            print("\n" + "=" * 60)
            print("PUBLISH PREVIEW (--dry-run)")
            print("=" * 60)
            print(f"\nSkill would be published to registry with:")
            print(f"  Registry: {registry_url}")
            print(f"  Name:     {manifest.skill_name}")
            print(f"  Version:  {manifest.skill_version}")
            print(f"  Author:   {manifest.author}")
            print(f"  Files:    {len(manifest.files)}")
            print(f"  Signer:   {manifest.signer.identity}")
            print(f"  Key:      {manifest.signer.key_fingerprint}")
            print("=" * 60)
            return 0

        # Check if identity is registered
        print(f"\nChecking identity registration at {registry_url}...")
        try:
            resp = requests.get(f"{registry_url}/identities", timeout=10)
            resp.raise_for_status()
            identities = resp.json()

            # Look for matching email
            registered = any(
                ident.get('email', '').lower() == manifest.author.lower()
                for ident in identities
            )

            if not registered or args.register_identity:
                print(f"\nIdentity {manifest.author} not registered with registry")

                if args.register_identity or config.registry_auto_register:
                    print("Registering identity...")

                    # Get public key for registration
                    if key_type == 'ssh':
                        # Read SSH public key
                        signing_key = config.signing_key or args.key
                        if signing_key:
                            pubkey_path = f"{signing_key}.pub"
                            if os.path.exists(pubkey_path):
                                with open(pubkey_path, 'r') as f:
                                    pubkey = f.read().strip()
                            else:
                                print(f"Error: Public key not found: {pubkey_path}", file=sys.stderr)
                                return 1
                        else:
                            print("Error: Cannot determine public key for registration", file=sys.stderr)
                            return 1
                    else:  # GPG
                        from . import gpg_signer
                        pubkey = gpg_signer.export_gpg_pubkey(manifest.author)
                        if not pubkey:
                            print(f"Error: Could not export GPG public key", file=sys.stderr)
                            return 1

                    # Register identity
                    identity_data = {
                        "name": manifest.signer.identity,
                        "email": manifest.author,
                        "pubkey": pubkey
                    }

                    resp = requests.post(
                        f"{registry_url}/identities/request",
                        json=identity_data,
                        timeout=10
                    )

                    if resp.status_code == 201:
                        print("✓ Identity registration requested")
                        print("\nNote: An admin must approve your identity before you can publish.")
                        print("Please contact the registry administrator.")
                        return 0
                    else:
                        print(f"✗ Identity registration failed: {resp.status_code}", file=sys.stderr)
                        print(resp.text, file=sys.stderr)
                        return 1
                else:
                    print("Error: Identity not registered. Use --register-identity to register.", file=sys.stderr)
                    return 1

        except requests.exceptions.RequestException as e:
            print(f"Error: Could not connect to registry: {e}", file=sys.stderr)
            return 1

        # Package skill into tar.gz
        print("\nPackaging skill...")
        with tempfile.NamedTemporaryFile(suffix='.tar.gz', delete=False) as tmp:
            tarball_path = tmp.name

        try:
            with tarfile.open(tarball_path, 'w:gz') as tar:
                for file_path in manifest.files.keys():
                    full_path = skill_dir / file_path
                    tar.add(full_path, arcname=file_path)

            print(f"✓ Created package: {len(manifest.files)} files")

            # Submit to registry
            print(f"\nSubmitting to registry at {registry_url}...")

            with open(tarball_path, 'rb') as package_file:
                files = {
                    'package': (f"{manifest.skill_name}-{manifest.skill_version}.tar.gz", package_file, 'application/gzip'),
                }
                data = {
                    'manifest': manifest.to_json()
                }

                resp = requests.post(
                    f"{registry_url}/skills/submit",
                    files=files,
                    data=data,
                    timeout=60
                )

            if resp.status_code == 201:
                print("✓ Skill published successfully!")
                result_data = resp.json()
                if 'url' in result_data:
                    print(f"\nSkill URL: {result_data['url']}")
                return 0
            elif resp.status_code == 409:
                print(f"✗ Skill version already exists: {manifest.skill_name} v{manifest.skill_version}", file=sys.stderr)
                return 1
            elif resp.status_code == 403:
                print(f"✗ Identity not approved by registry admin yet", file=sys.stderr)
                print("Please wait for admin approval or contact the registry administrator.", file=sys.stderr)
                return 1
            else:
                print(f"✗ Publish failed: {resp.status_code}", file=sys.stderr)
                print(resp.text, file=sys.stderr)
                return 1

        finally:
            # Cleanup temp tarball
            if os.path.exists(tarball_path):
                os.unlink(tarball_path)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def cmd_inspect(args):
    """Inspect a skill manifest without verifying."""
    skill_dir = Path(args.skill_dir).resolve()
    manifest_path = skill_dir / "MANIFEST.sig.json"

    if not manifest_path.exists():
        print(f"Error: No manifest found: {manifest_path}", file=sys.stderr)
        return 1

    try:
        manifest = load_manifest(str(manifest_path))

        print(f"Skill: {manifest.skill_name} v{manifest.skill_version}")
        print(f"Author: {manifest.author}")
        print(f"Timestamp: {manifest.timestamp}")
        print(f"Files: {len(manifest.files)}")

        if manifest.dependencies:
            print(f"Dependencies: {len(manifest.dependencies)}")
            for dep in manifest.dependencies:
                print(f"  - {dep.name} v{dep.version}")

        if manifest.signer:
            print(f"Signed by: {manifest.signer.identity}")
            print(f"Key: {manifest.signer.key_fingerprint}")
        else:
            print("Status: UNSIGNED")

        if args.verbose:
            print("\nFiles:")
            for path, entry in sorted(manifest.files.items()):
                print(f"  {path}")
                print(f"    SHA256: {entry.sha256}")
                print(f"    Size: {entry.size} bytes")

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_setup(args):
    """Run the interactive setup wizard."""
    from .setup_wizard import setup_wizard
    return setup_wizard()


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="skill-signer",
        description="Cryptographic signing for AI agent skills"
    )

    # Check SSH version first
    ok, msg = check_ssh_version()
    if not ok:
        print(f"Error: {msg}", file=sys.stderr)
        print("skill-signer requires OpenSSH 8.0+ for ssh-keygen -Y support", file=sys.stderr)
        return 1

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # skill-signer sign
    sign_parser = subparsers.add_parser('sign', help='Sign a skill directory')
    sign_parser.add_argument('skill_dir', help='Path to skill directory')
    sign_parser.add_argument('--key', help='Path to SSH private key, GPG key ID, or use config signing.key')
    sign_parser.add_argument(
        '--identity',
        help='Signer identity (email); auto-discovered from config, <key>.meta, or key comment'
    )
    sign_parser.add_argument('--version', help='Skill version (auto-detected if not provided)')
    sign_parser.add_argument('--key-type', choices=['ssh', 'gpg'], help='Key type (auto-detected if not provided)')
    sign_parser.set_defaults(func=cmd_sign)

    # skill-signer verify
    verify_parser = subparsers.add_parser('verify', help='Verify a signed skill directory')
    verify_parser.add_argument('skill_dir', help='Path to skill directory')
    verify_parser.add_argument('--allowed-signers', help=f'Path to allowed_signers file (default: {DEFAULT_ALLOWED_SIGNERS})')
    verify_parser.set_defaults(func=cmd_verify)

    # skill-signer keygen
    keygen_parser = subparsers.add_parser('keygen', help='Generate SSH or GPG keypair')
    keygen_parser.add_argument('--output', help='Output path for private key (SSH) or directory for GPG backup')
    keygen_parser.add_argument('--type', choices=['ssh', 'gpg'], default='ssh', help='Key type to generate (default: ssh)')
    keygen_parser.add_argument(
        '--name',
        help='Key name / identity (e.g. "John Doe" or "user@example.com")'
    )
    keygen_parser.add_argument('--email', help='Email address (required for GPG)')
    # --comment is kept as a hidden backward-compatible alias for --name
    keygen_parser.add_argument('--comment', help=argparse.SUPPRESS)
    keygen_parser.set_defaults(func=cmd_keygen)

    # skill-signer trust
    trust_parser = subparsers.add_parser('trust', help='Manage trusted signers')
    trust_subparsers = trust_parser.add_subparsers(dest='trust_command', help='Trust commands')

    # trust add  — identity is optional; parsed from key comment if omitted
    trust_add_parser = trust_subparsers.add_parser('add', help='Add trusted signer')
    trust_add_parser.add_argument(
        'positionals',
        nargs='+',
        metavar='arg',
        help='[identity] pubkey — identity is optional and will be read from '
             'the key comment if omitted'
    )
    trust_add_parser.add_argument(
        '--allowed-signers',
        help=f'Path to allowed_signers file (default: {DEFAULT_ALLOWED_SIGNERS})'
    )
    trust_add_parser.set_defaults(func=cmd_trust_add)

    # trust revoke
    trust_revoke_parser = trust_subparsers.add_parser('revoke', help='Revoke trusted signer')
    trust_revoke_parser.add_argument('identity', help='Signer identity to revoke')
    trust_revoke_parser.add_argument('--allowed-signers', help=f'Path to allowed_signers file (default: {DEFAULT_ALLOWED_SIGNERS})')
    trust_revoke_parser.set_defaults(func=cmd_trust_revoke)

    # trust list
    trust_list_parser = trust_subparsers.add_parser('list', help='List trusted signers')
    trust_list_parser.add_argument('--allowed-signers', help=f'Path to allowed_signers file (default: {DEFAULT_ALLOWED_SIGNERS})')
    trust_list_parser.set_defaults(func=cmd_trust_list)

    # skill-signer inspect
    inspect_parser = subparsers.add_parser('inspect', help='Inspect skill manifest')
    inspect_parser.add_argument('skill_dir', help='Path to skill directory')
    inspect_parser.add_argument('--verbose', '-v', action='store_true', help='Show file details')
    inspect_parser.set_defaults(func=cmd_inspect)

    # skill-signer publish
    publish_parser = subparsers.add_parser('publish', help='Publish a signed skill to a registry')
    publish_parser.add_argument('skill_dir', help='Path to skill directory')
    publish_parser.add_argument('--registry', help='Registry URL (default: from config or SKILL_REGISTRY_URL env var)')
    publish_parser.add_argument('--register-identity', action='store_true', help='Force identity registration')
    publish_parser.add_argument('--dry-run', action='store_true', help='Preview without publishing')
    publish_parser.add_argument('--allowed-signers', help=f'Path to allowed_signers file (default: {DEFAULT_ALLOWED_SIGNERS})')
    publish_parser.add_argument('--key', help='Path to signing key (for identity registration)')
    publish_parser.set_defaults(func=cmd_publish)

    # skill-signer setup
    setup_parser = subparsers.add_parser('setup', help='Run interactive setup wizard')
    setup_parser.set_defaults(func=cmd_setup)

    # Parse and execute
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    if hasattr(args, 'func'):
        return args.func(args)
    else:
        if args.command == 'trust' and not args.trust_command:
            trust_parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
