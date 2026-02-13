#!/usr/bin/env python3
"""
Tests for SSH signing and verification.
"""

import os
import tempfile
from pathlib import Path

import pytest

from lib.ssh_signer import (
    check_ssh_version,
    get_key_fingerprint,
    generate_keypair,
    sign_data,
    verify_data,
    SignatureResult,
    VerificationResult,
    NAMESPACE,
)


def test_check_ssh_version():
    """Test SSH version checking."""
    ok, msg = check_ssh_version()
    
    # Should succeed on modern systems
    assert isinstance(ok, bool)
    assert isinstance(msg, str)
    
    if ok:
        assert "OpenSSH" in msg
    else:
        assert "Error" in msg or "need" in msg


def test_generate_keypair():
    """Test SSH keypair generation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "test_key")
        
        success, message = generate_keypair(key_path, "test-comment")
        
        assert success
        assert "Generated" in message
        assert os.path.exists(key_path)  # private key
        assert os.path.exists(f"{key_path}.pub")  # public key
        
        # Check key content
        with open(f"{key_path}.pub", 'r') as f:
            pubkey = f.read().strip()
        
        assert pubkey.startswith("ssh-ed25519")
        assert "test-comment" in pubkey


def test_generate_keypair_existing():
    """Test keypair generation with existing key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "existing_key")
        
        # Create existing key
        Path(key_path).touch()
        
        success, message = generate_keypair(key_path, "test")
        
        assert not success
        assert "already exists" in message


def test_get_key_fingerprint():
    """Test key fingerprint extraction."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "test_key")
        
        # Generate a key first
        success, _ = generate_keypair(key_path, "test")
        assert success
        
        # Test with private key
        fingerprint = get_key_fingerprint(key_path)
        assert fingerprint is not None
        assert fingerprint.startswith("SHA256:")
        
        # Test with public key
        fingerprint_pub = get_key_fingerprint(f"{key_path}.pub")
        assert fingerprint_pub == fingerprint
        
        # Test with nonexistent key
        fingerprint_none = get_key_fingerprint("/nonexistent/key")
        assert fingerprint_none is None


def test_sign_verify_roundtrip():
    """Test signing and verification round trip."""
    # Skip if SSH version doesn't support signing
    ok, _ = check_ssh_version()
    if not ok:
        pytest.skip("OpenSSH 8.0+ required for signing")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "test_key")
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        # Generate test keypair
        success, _ = generate_keypair(key_path, "test-signer")
        assert success
        
        # Create allowed_signers file
        with open(f"{key_path}.pub", 'r') as f:
            pubkey = f.read().strip()
        
        with open(allowed_signers, 'w') as f:
            f.write(f'test@example.com namespaces="{NAMESPACE}" {pubkey}\n')
        
        # Test data
        test_data = b"Hello, skill signing world!"
        identity = "test@example.com"
        
        # Sign the data
        sign_result = sign_data(test_data, key_path)
        
        assert sign_result.success
        assert sign_result.signature is not None
        assert sign_result.error is None
        assert "-----BEGIN SSH SIGNATURE-----" in sign_result.signature
        
        # Verify the signature
        verify_result = verify_data(
            test_data,
            sign_result.signature,
            allowed_signers,
            identity
        )
        
        assert verify_result.valid
        assert verify_result.signer == identity
        assert verify_result.error is None


def test_sign_nonexistent_key():
    """Test signing with nonexistent key."""
    result = sign_data(b"test data", "/nonexistent/key")
    
    assert not result.success
    assert "Key not found" in result.error


def test_verify_invalid_signature():
    """Test verification with invalid signature."""
    # Skip if SSH version doesn't support signing
    ok, _ = check_ssh_version()
    if not ok:
        pytest.skip("OpenSSH 8.0+ required for signing")
        
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "test_key") 
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        # Generate keypair and allowed_signers
        success, _ = generate_keypair(key_path, "test")
        assert success
        
        with open(f"{key_path}.pub", 'r') as f:
            pubkey = f.read().strip()
            
        with open(allowed_signers, 'w') as f:
            f.write(f'test@example.com namespaces="{NAMESPACE}" {pubkey}\n')
        
        # Create valid signature
        test_data = b"original data"
        sign_result = sign_data(test_data, key_path)
        assert sign_result.success
        
        # Try to verify different data with same signature (should fail)
        different_data = b"modified data"
        verify_result = verify_data(
            different_data,
            sign_result.signature,
            allowed_signers,
            "test@example.com"
        )
        
        assert not verify_result.valid
        assert verify_result.error is not None


def test_verify_wrong_identity():
    """Test verification with wrong identity."""
    # Skip if SSH version doesn't support signing
    ok, _ = check_ssh_version()
    if not ok:
        pytest.skip("OpenSSH 8.0+ required for signing")
        
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "test_key")
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        # Generate keypair and allowed_signers
        success, _ = generate_keypair(key_path, "test")
        assert success
        
        with open(f"{key_path}.pub", 'r') as f:
            pubkey = f.read().strip()
            
        with open(allowed_signers, 'w') as f:
            f.write(f'correct@example.com namespaces="{NAMESPACE}" {pubkey}\n')
        
        # Sign with key
        test_data = b"test data"
        sign_result = sign_data(test_data, key_path)
        assert sign_result.success
        
        # Try to verify with wrong identity
        verify_result = verify_data(
            test_data,
            sign_result.signature,
            allowed_signers,
            "wrong@example.com"  # Wrong identity
        )
        
        assert not verify_result.valid


def test_verify_nonexistent_allowed_signers():
    """Test verification with missing allowed_signers file."""
    result = verify_data(
        b"test data",
        "fake-signature",
        "/nonexistent/allowed_signers",
        "test@example.com"
    )
    
    assert not result.valid
    assert "allowed_signers not found" in result.error


def test_signature_result():
    """Test SignatureResult dataclass."""
    # Success case
    success_result = SignatureResult(success=True, signature="sig-data")
    assert success_result.success
    assert success_result.signature == "sig-data"
    assert success_result.error is None
    
    # Error case
    error_result = SignatureResult(success=False, error="Something went wrong")
    assert not error_result.success
    assert error_result.signature is None
    assert error_result.error == "Something went wrong"


def test_verification_result():
    """Test VerificationResult dataclass.""" 
    # Valid case
    valid_result = VerificationResult(valid=True, signer="test@example.com")
    assert valid_result.valid
    assert valid_result.signer == "test@example.com"
    assert valid_result.error is None
    
    # Invalid case
    invalid_result = VerificationResult(valid=False, error="Bad signature")
    assert not invalid_result.valid
    assert invalid_result.signer is None
    assert invalid_result.error == "Bad signature"


if __name__ == "__main__":
    pytest.main([__file__])