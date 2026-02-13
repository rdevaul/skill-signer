#!/usr/bin/env python3
"""
SSH-based signing and verification for skill manifests.

Uses ssh-keygen -Y sign/verify (OpenSSH 8.0+) with Ed25519 keys.
"""

import subprocess
import tempfile
import os
import json
from pathlib import Path
from typing import Optional, Tuple
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


NAMESPACE = "skill-manifest"


def check_ssh_version() -> Tuple[bool, str]:
    """Check if OpenSSH version supports signing (8.0+)."""
    try:
        result = subprocess.run(
            ["ssh", "-V"],
            capture_output=True,
            text=True
        )
        version_str = result.stderr.strip()  # ssh -V outputs to stderr
        # Parse version like "OpenSSH_9.0p1, ..."
        if "OpenSSH_" in version_str:
            version_part = version_str.split("OpenSSH_")[1].split(",")[0]
            major = int(version_part.split(".")[0].split("p")[0])
            if major >= 8:
                return True, version_str
            return False, f"OpenSSH {major}.x found, need 8.0+"
        return False, f"Could not parse version: {version_str}"
    except Exception as e:
        return False, f"Error checking SSH version: {e}"


def get_key_fingerprint(key_path: str) -> Optional[str]:
    """Get SHA256 fingerprint of an SSH key."""
    try:
        result = subprocess.run(
            ["ssh-keygen", "-lf", key_path],
            capture_output=True,
            text=True,
            check=True
        )
        # Output: "256 SHA256:xxx... comment (ED25519)"
        parts = result.stdout.strip().split()
        if len(parts) >= 2:
            return parts[1]  # SHA256:...
        return None
    except subprocess.CalledProcessError:
        return None


def sign_data(data: bytes, key_path: str, namespace: str = NAMESPACE) -> SignatureResult:
    """
    Sign data using SSH key.
    
    Args:
        data: Raw bytes to sign
        key_path: Path to private SSH key
        namespace: Signature namespace (default: skill-manifest)
        
    Returns:
        SignatureResult with signature or error
    """
    # Verify key exists
    key_path = os.path.expanduser(key_path)
    if not os.path.exists(key_path):
        return SignatureResult(success=False, error=f"Key not found: {key_path}")
    
    # Create temp file for data
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.data') as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    
    sig_path = tmp_path + ".sig"
    
    try:
        # Sign using ssh-keygen
        result = subprocess.run(
            [
                "ssh-keygen", "-Y", "sign",
                "-f", key_path,
                "-n", namespace,
                tmp_path
            ],
            capture_output=True,
            text=True
        )
        
        if result.returncode != 0:
            return SignatureResult(
                success=False,
                error=f"ssh-keygen sign failed: {result.stderr}"
            )
        
        # Read signature file
        if os.path.exists(sig_path):
            with open(sig_path, 'r') as f:
                signature = f.read()
            return SignatureResult(success=True, signature=signature)
        else:
            return SignatureResult(
                success=False,
                error="Signature file not created"
            )
            
    finally:
        # Cleanup
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        if os.path.exists(sig_path):
            os.unlink(sig_path)


def verify_data(
    data: bytes,
    signature: str,
    allowed_signers_path: str,
    identity: str,
    namespace: str = NAMESPACE
) -> VerificationResult:
    """
    Verify signature using SSH allowed_signers.
    
    Args:
        data: Raw bytes that were signed
        signature: SSH signature string
        allowed_signers_path: Path to allowed_signers file
        identity: Expected signer identity (email)
        namespace: Signature namespace
        
    Returns:
        VerificationResult with validity and signer info
    """
    allowed_signers_path = os.path.expanduser(allowed_signers_path)
    if not os.path.exists(allowed_signers_path):
        return VerificationResult(
            valid=False,
            error=f"allowed_signers not found: {allowed_signers_path}"
        )
    
    # Create temp files
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.data') as tmp:
        tmp.write(data)
        data_path = tmp.name
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.sig') as tmp:
        tmp.write(signature)
        sig_path = tmp.name
    
    try:
        # Verify using ssh-keygen - reads data from stdin
        with open(data_path, 'r') as data_file:
            result = subprocess.run(
                [
                    "ssh-keygen", "-Y", "verify",
                    "-f", allowed_signers_path,
                    "-I", identity,
                    "-n", namespace,
                    "-s", sig_path
                ],
                stdin=data_file,
                capture_output=True,
                text=True
            )
        
        if result.returncode == 0:
            return VerificationResult(valid=True, signer=identity)
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
    output_path: str,
    comment: str = "skill-signing-key"
) -> Tuple[bool, str]:
    """
    Generate Ed25519 keypair for skill signing.
    
    Args:
        output_path: Where to save the private key (public key is .pub)
        comment: Key comment/identifier
        
    Returns:
        Tuple of (success, message)
    """
    output_path = os.path.expanduser(output_path)
    
    # Don't overwrite existing keys
    if os.path.exists(output_path):
        return False, f"Key already exists: {output_path}"
    
    try:
        result = subprocess.run(
            [
                "ssh-keygen",
                "-t", "ed25519",
                "-f", output_path,
                "-N", "",  # No passphrase (user can add one)
                "-C", comment
            ],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            fingerprint = get_key_fingerprint(output_path)
            return True, f"Generated {output_path} ({fingerprint})"
        else:
            return False, f"Key generation failed: {result.stderr}"
            
    except Exception as e:
        return False, f"Error generating keypair: {e}"


if __name__ == "__main__":
    # Self-test
    print("Checking SSH version...")
    ok, msg = check_ssh_version()
    print(f"  {'✓' if ok else '✗'} {msg}")
    
    if ok:
        print("\nGenerating test keypair...")
        with tempfile.TemporaryDirectory() as tmpdir:
            key_path = os.path.join(tmpdir, "test_key")
            ok, msg = generate_keypair(key_path, "test")
            print(f"  {'✓' if ok else '✗'} {msg}")
            
            if ok:
                print("\nTesting sign/verify...")
                test_data = b"Hello, skill signing!"
                
                result = sign_data(test_data, key_path)
                print(f"  Sign: {'✓' if result.success else '✗'} {result.error or 'OK'}")
                
                if result.success:
                    # Create allowed_signers
                    with open(f"{key_path}.pub", 'r') as f:
                        pubkey = f.read().strip()
                    
                    allowed_path = os.path.join(tmpdir, "allowed_signers")
                    with open(allowed_path, 'w') as f:
                        f.write(f"test@example.com namespaces=\"skill-manifest\" {pubkey}\n")
                    
                    verify_result = verify_data(
                        test_data,
                        result.signature,
                        allowed_path,
                        "test@example.com"
                    )
                    print(f"  Verify: {'✓' if verify_result.valid else '✗'} {verify_result.error or 'OK'}")
