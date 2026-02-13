#!/usr/bin/env python3
"""
CLI for skill-signer: cryptographic signing for AI agent skills.
"""

import os
import sys
import argparse
import json
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
    
    key_path = os.path.expanduser(args.key)
    if not os.path.exists(key_path):
        print(f"Error: Key not found: {key_path}", file=sys.stderr)
        return 1
    
    try:
        # Create manifest
        print(f"Creating manifest for {skill_dir.name}...")
        manifest = create_manifest(
            str(skill_dir),
            author=args.identity,
            version=args.version
        )
        
        print(f"Found {len(manifest.files)} files")
        
        # Sign manifest
        print(f"Signing with key {key_path}...")
        signed_manifest = sign_manifest(manifest, key_path, args.identity)
        
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
    
    allowed_signers = args.allowed_signers or DEFAULT_ALLOWED_SIGNERS
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
        
        result = verify_data(
            payload,
            manifest.signature,
            allowed_signers,
            manifest.signer.identity
        )
        
        if result.valid:
            print("✓ Signature is valid")
            
            # TODO: Verify file hashes
            print(f"✓ Manifest covers {len(manifest.files)} files")
            
            return 0
        else:
            print(f"✗ Signature verification failed: {result.error}")
            return 1
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


def cmd_keygen(args):
    """Generate a new SSH Ed25519 keypair."""
    output_path = os.path.expanduser(args.output)
    
    success, message = generate_keypair(output_path, args.comment or "skill-signing-key")
    
    if success:
        print(f"✓ {message}")
        print(f"Private key: {output_path}")
        print(f"Public key:  {output_path}.pub")
        
        # Show how to add to trusted signers
        print(f"\nTo trust this key:")
        print(f"skill-signer trust add <identity> {output_path}.pub")
        
        return 0
    else:
        print(f"Error: {message}", file=sys.stderr)
        return 1


def cmd_trust_add(args):
    """Add a trusted signer."""
    ensure_config_dir()
    allowed_signers = args.allowed_signers or DEFAULT_ALLOWED_SIGNERS
    
    try:
        # Handle URL vs file path
        if args.pubkey.startswith(('http://', 'https://')):
            print(f"Fetching public key from {args.pubkey}...")
            pubkey_content = fetch_pubkey(args.pubkey)
        else:
            pubkey_path = os.path.expanduser(args.pubkey)
            if not os.path.exists(pubkey_path):
                print(f"Error: Public key not found: {pubkey_path}", file=sys.stderr)
                return 1
            
            with open(pubkey_path, 'r') as f:
                pubkey_content = f.read().strip()
        
        print(f"Adding signer {args.identity}...")
        add_signer(args.identity, pubkey_content, allowed_signers)
        
        print(f"✓ Added {args.identity} to {allowed_signers}")
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
    sign_parser.add_argument('--key', required=True, help='Path to SSH private key')
    sign_parser.add_argument('--identity', required=True, help='Signer identity (email)')
    sign_parser.add_argument('--version', help='Skill version (auto-detected if not provided)')
    sign_parser.set_defaults(func=cmd_sign)
    
    # skill-signer verify
    verify_parser = subparsers.add_parser('verify', help='Verify a signed skill directory')
    verify_parser.add_argument('skill_dir', help='Path to skill directory')
    verify_parser.add_argument('--allowed-signers', help=f'Path to allowed_signers file (default: {DEFAULT_ALLOWED_SIGNERS})')
    verify_parser.set_defaults(func=cmd_verify)
    
    # skill-signer keygen
    keygen_parser = subparsers.add_parser('keygen', help='Generate SSH Ed25519 keypair')
    keygen_parser.add_argument('--output', required=True, help='Output path for private key')
    keygen_parser.add_argument('--comment', help='Key comment (default: skill-signing-key)')
    keygen_parser.set_defaults(func=cmd_keygen)
    
    # skill-signer trust
    trust_parser = subparsers.add_parser('trust', help='Manage trusted signers')
    trust_subparsers = trust_parser.add_subparsers(dest='trust_command', help='Trust commands')
    
    # trust add
    trust_add_parser = trust_subparsers.add_parser('add', help='Add trusted signer')
    trust_add_parser.add_argument('identity', help='Signer identity (email)')
    trust_add_parser.add_argument('pubkey', help='Path to public key file or URL')
    trust_add_parser.add_argument('--allowed-signers', help=f'Path to allowed_signers file (default: {DEFAULT_ALLOWED_SIGNERS})')
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