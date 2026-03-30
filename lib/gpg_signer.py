#!/usr/bin/env python3
"""
GPG-based signing and verification for skill manifests.

Uses gpg CLI for signing/verification with GPG keys.
"""

import subprocess
import tempfile
import os
import json
import re
from pathlib import Path
from typing import Optional, Tuple, List, Dict
from dataclasses import dataclass


@dataclass
class SignatureResult:
    """Result of a signing operation."""
    success: bool
    signature: Optional[str] = None
    error: Optional[str] = None


@dataclass
class VerificationResult:
    """Result of a verification operation."""
    valid: bool
    signer: Optional[str] = None
    error: Optional[str] = None


def check_gpg_available() -> Tuple[bool, str]:
    """Check if GPG is installed and available."""
    try:
        result = subprocess.run(
            ["gpg", "--version"],
            capture_output=True,
            text=True,
            check=False
        )
        if result.returncode == 0:
            # Parse version from first line: "gpg (GnuPG) X.Y.Z"
            version_line = result.stdout.split('\n')[0]
            return True, version_line
        return False, "gpg command failed"
    except FileNotFoundError:
        return False, "gpg not found. Install GnuPG: https://gnupg.org/download/"
    except Exception as e:
        return False, f"Error checking GPG: {e}"


def list_gpg_keys() -> List[Dict[str, str]]:
    """
    List available GPG secret keys.

    Returns:
        List of dicts with 'key_id', 'fingerprint', 'uid' fields
    """
    try:
        result = subprocess.run(
            ["gpg", "--list-secret-keys", "--with-colons"],
            capture_output=True,
            text=True,
            check=True
        )

        keys = []
        current_key = {}

        for line in result.stdout.split('\n'):
            if not line:
                continue

            fields = line.split(':')
            record_type = fields[0]

            if record_type == 'sec':
                # Secret key record
                if current_key:
                    keys.append(current_key)
                current_key = {
                    'key_id': fields[4][-8:],  # Last 8 chars of key ID
                    'fingerprint': '',
                    'uid': ''
                }
            elif record_type == 'fpr':
                # Fingerprint record
                current_key['fingerprint'] = fields[9]
            elif record_type == 'uid':
                # User ID record
                current_key['uid'] = fields[9]

        if current_key:
            keys.append(current_key)

        return keys

    except subprocess.CalledProcessError:
        return []
    except Exception:
        return []


def get_gpg_key_fingerprint(key_id: str) -> Optional[str]:
    """
    Get full fingerprint of a GPG key.

    Args:
        key_id: Key ID or email address

    Returns:
        Full fingerprint or None if not found
    """
    try:
        result = subprocess.run(
            ["gpg", "--list-keys", "--with-colons", key_id],
            capture_output=True,
            text=True,
            check=True
        )

        for line in result.stdout.split('\n'):
            if line.startswith('fpr:'):
                fields = line.split(':')
                return fields[9]

        return None

    except subprocess.CalledProcessError:
        return None


def export_gpg_pubkey(key_id: str) -> Optional[str]:
    """
    Export GPG public key in ASCII-armored format.

    Args:
        key_id: Key ID or email address

    Returns:
        Armored public key string or None on error
    """
    try:
        result = subprocess.run(
            ["gpg", "--armor", "--export", key_id],
            capture_output=True,
            text=True,
            check=True
        )

        if result.stdout.strip():
            return result.stdout.strip()
        return None

    except subprocess.CalledProcessError:
        return None


def import_gpg_pubkey(pubkey: str) -> Tuple[bool, str]:
    """
    Import a GPG public key.

    Args:
        pubkey: ASCII-armored public key

    Returns:
        Tuple of (success, message)
    """
    try:
        result = subprocess.run(
            ["gpg", "--import"],
            input=pubkey,
            capture_output=True,
            text=True,
            check=False
        )

        # GPG writes import results to stderr
        if result.returncode == 0:
            return True, result.stderr.strip()
        else:
            return False, result.stderr.strip()

    except Exception as e:
        return False, f"Error importing key: {e}"


def sign_data(data: bytes, key_id: str) -> SignatureResult:
    """
    Sign data using GPG key.

    Args:
        data: Raw bytes to sign
        key_id: GPG key ID or email address

    Returns:
        SignatureResult with signature or error
    """
    try:
        # Sign using gpg --detach-sign --armor
        result = subprocess.run(
            ["gpg", "--detach-sign", "--armor", "--local-user", key_id],
            input=data,
            capture_output=True,
            check=False
        )

        if result.returncode != 0:
            return SignatureResult(
                success=False,
                error=f"gpg sign failed: {result.stderr.decode('utf-8', errors='replace')}"
            )

        # Get armored signature
        signature = result.stdout.decode('utf-8')
        return SignatureResult(success=True, signature=signature)

    except Exception as e:
        return SignatureResult(
            success=False,
            error=f"Error signing data: {e}"
        )


def verify_data(
    data: bytes,
    signature: str,
    key_id: str
) -> VerificationResult:
    """
    Verify GPG signature.

    Args:
        data: Raw bytes that were signed
        signature: ASCII-armored signature
        key_id: Expected signer key ID or email

    Returns:
        VerificationResult with validity and signer info
    """
    # Create temp files for data and signature
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.data') as tmp:
        tmp.write(data)
        data_path = tmp.name

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sig') as tmp:
        tmp.write(signature)
        sig_path = tmp.name

    try:
        # Verify using gpg --verify
        result = subprocess.run(
            ["gpg", "--verify", sig_path, data_path],
            capture_output=True,
            text=True,
            check=False
        )

        # GPG writes verification results to stderr
        stderr = result.stderr.lower()

        if result.returncode == 0 and "good signature" in stderr:
            # Extract signer from output
            # Look for "Good signature from \"Name <email>\""
            match = re.search(r'good signature from "([^"]+)"', stderr, re.IGNORECASE)
            signer = match.group(1) if match else key_id

            return VerificationResult(valid=True, signer=signer)
        else:
            return VerificationResult(
                valid=False,
                error=f"Verification failed: {result.stderr.strip()}"
            )

    finally:
        if os.path.exists(data_path):
            os.unlink(data_path)
        if os.path.exists(sig_path):
            os.unlink(sig_path)


def generate_keypair(
    name: str,
    email: str,
    output_dir: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Generate GPG keypair using batch mode.

    Args:
        name: Real name for the key
        email: Email address for the key
        output_dir: Optional directory to export keys (for backup)

    Returns:
        Tuple of (success, message)
    """
    # Create batch file for key generation
    batch_params = f"""
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: {name}
Name-Email: {email}
Expire-Date: 0
%no-protection
%commit
""".strip()

    try:
        result = subprocess.run(
            ["gpg", "--batch", "--gen-key"],
            input=batch_params,
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode != 0:
            return False, f"Key generation failed: {result.stderr}"

        # Get the fingerprint of the newly generated key
        fingerprint = get_gpg_key_fingerprint(email)
        if not fingerprint:
            return False, "Key generated but could not retrieve fingerprint"

        message = f"Generated GPG key for {email}\nFingerprint: {fingerprint}"

        # Export keys if output directory specified
        if output_dir:
            output_dir = os.path.expanduser(output_dir)
            os.makedirs(output_dir, exist_ok=True)

            # Export public key
            pubkey = export_gpg_pubkey(email)
            if pubkey:
                pubkey_path = os.path.join(output_dir, f"{email}.asc")
                with open(pubkey_path, 'w') as f:
                    f.write(pubkey)
                message += f"\nPublic key: {pubkey_path}"

        return True, message

    except Exception as e:
        return False, f"Error generating keypair: {e}"


if __name__ == "__main__":
    # Self-test
    print("Checking GPG availability...")
    ok, msg = check_gpg_available()
    print(f"  {'✓' if ok else '✗'} {msg}")

    if ok:
        print("\nListing GPG secret keys...")
        keys = list_gpg_keys()
        if keys:
            print(f"  Found {len(keys)} secret key(s):")
            for key in keys:
                print(f"    {key['key_id']}: {key['uid']}")
        else:
            print("  No secret keys found")
            print("\nTo generate a test key:")
            print("  gpg --quick-gen-key 'Test User <test@example.com>' rsa4096")

        # Test sign/verify if keys available
        if keys:
            print("\nTesting sign/verify with first key...")
            test_data = b"Hello, GPG skill signing!"
            key_id = keys[0]['key_id']

            result = sign_data(test_data, key_id)
            print(f"  Sign: {'✓' if result.success else '✗'} {result.error or 'OK'}")

            if result.success:
                verify_result = verify_data(test_data, result.signature, key_id)
                print(f"  Verify: {'✓' if verify_result.valid else '✗'} {verify_result.error or 'OK'}")
                if verify_result.valid:
                    print(f"  Signer: {verify_result.signer}")
