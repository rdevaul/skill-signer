#!/usr/bin/env python3
"""
Tests for trust management (allowed_signers handling).
"""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

import pytest

from lib.trust import (
    parse_allowed_signers_line,
    add_signer,
    revoke_signer,
    list_signers,
    fetch_pubkey,
)


def test_parse_allowed_signers_line():
    """Test parsing of allowed_signers file lines."""
    # Valid line with namespaces
    line1 = 'test@example.com namespaces="skill-manifest" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqP test@example.com'
    parsed1 = parse_allowed_signers_line(line1)
    
    assert parsed1 is not None
    assert parsed1['identity'] == 'test@example.com'
    assert parsed1['namespaces'] == 'skill-manifest'
    assert parsed1['algorithm'] == 'ssh-ed25519'
    assert parsed1['key'] == 'AAAAC3NzaC1lZDI1NTE5AAAAIKqP'
    assert parsed1['comment'] == 'test@example.com'
    assert not parsed1['revoked']
    assert not parsed1['cert_authority']
    
    # Valid line without namespaces
    line2 = 'user@domain.com ssh-rsa AAAAB3NzaC1yc2E user-key'
    parsed2 = parse_allowed_signers_line(line2)
    
    assert parsed2 is not None
    assert parsed2['identity'] == 'user@domain.com'
    assert parsed2['namespaces'] is None
    assert parsed2['algorithm'] == 'ssh-rsa'
    
    # Revoked line
    line3 = '# REVOKED: test@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqP test'
    parsed3 = parse_allowed_signers_line(line3)
    
    assert parsed3 is not None
    assert parsed3['identity'] == 'test@example.com'
    assert parsed3['revoked']
    
    # Comment line
    line4 = '# This is a comment'
    parsed4 = parse_allowed_signers_line(line4)
    assert parsed4 is None
    
    # Empty line
    line5 = ''
    parsed5 = parse_allowed_signers_line(line5)
    assert parsed5 is None
    
    # Invalid line (too few parts)
    line6 = 'test@example.com'
    parsed6 = parse_allowed_signers_line(line6)
    assert parsed6 is None


def test_add_signer():
    """Test adding a signer to allowed_signers."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqP test@example.com"
        
        # Add first signer
        add_signer("test@example.com", pubkey, allowed_signers)
        
        # Verify file was created and contains our entry
        assert os.path.exists(allowed_signers)
        
        with open(allowed_signers, 'r') as f:
            content = f.read()
        
        assert 'test@example.com' in content
        assert 'ssh-ed25519' in content
        assert 'skill-manifest' in content
        assert 'AAAAC3NzaC1lZDI1NTE5AAAAIKqP' in content


def test_add_signer_duplicate():
    """Test adding duplicate signer."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqP test@example.com"
        
        # Add signer once
        add_signer("test@example.com", pubkey, allowed_signers)
        
        # Try to add same signer again (should fail)
        with pytest.raises(ValueError, match="already exists"):
            add_signer("test@example.com", pubkey, allowed_signers)


def test_add_signer_invalid_pubkey():
    """Test adding signer with invalid public key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        # Invalid key (not enough parts)
        with pytest.raises(ValueError, match="Invalid public key format"):
            add_signer("test@example.com", "invalid-key", allowed_signers)


def test_revoke_signer():
    """Test revoking a signer."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        # Create allowed_signers with multiple entries
        content = '''test1@example.com namespaces="skill-manifest" ssh-ed25519 AAAA1 test1
test2@example.com namespaces="skill-manifest" ssh-ed25519 AAAA2 test2
'''
        with open(allowed_signers, 'w') as f:
            f.write(content)
        
        # Revoke first signer
        revoke_signer("test1@example.com", allowed_signers)
        
        # Check file content
        with open(allowed_signers, 'r') as f:
            new_content = f.read()
        
        assert "# REVOKED: test1@example.com" in new_content
        assert "test2@example.com namespaces=" in new_content  # Should remain unchanged


def test_revoke_signer_not_found():
    """Test revoking non-existent signer."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        # Create empty file
        Path(allowed_signers).touch()
        
        # Try to revoke non-existent signer
        with pytest.raises(ValueError, match="No active signer found"):
            revoke_signer("nonexistent@example.com", allowed_signers)


def test_revoke_signer_missing_file():
    """Test revoking with missing allowed_signers file."""
    with pytest.raises(FileNotFoundError):
        revoke_signer("test@example.com", "/nonexistent/allowed_signers")


def test_list_signers():
    """Test listing signers from allowed_signers."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        # Create test file
        content = '''# Comment line
test1@example.com namespaces="skill-manifest" ssh-ed25519 AAAA1 test1
# REVOKED: test2@example.com ssh-ed25519 AAAA2 test2
test3@example.com cert-authority ssh-rsa AAAA3 test3

test4@example.com namespaces="other" ssh-ed25519 AAAA4 test4
'''
        with open(allowed_signers, 'w') as f:
            f.write(content)
        
        signers = list_signers(allowed_signers)
        
        # Should have 4 parsed entries (excluding comment)
        assert len(signers) == 4
        
        # Check first signer
        signer1 = signers[0]
        assert signer1['identity'] == 'test1@example.com'
        assert signer1['namespaces'] == 'skill-manifest'
        assert signer1['algorithm'] == 'ssh-ed25519'
        assert not signer1['revoked']
        assert not signer1['cert_authority']
        
        # Check revoked signer
        signer2 = signers[1]
        assert signer2['identity'] == 'test2@example.com'
        assert signer2['revoked']
        
        # Check cert-authority signer
        signer3 = signers[2]
        assert signer3['identity'] == 'test3@example.com'
        assert signer3['cert_authority']


def test_list_signers_missing_file():
    """Test listing signers from missing file."""
    signers = list_signers("/nonexistent/allowed_signers")
    assert signers == []


@patch('urllib.request.urlopen')
def test_fetch_pubkey_success(mock_urlopen):
    """Test successful public key fetching."""
    # Mock response with valid public key
    mock_response = mock_open(read_data=b'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqP test@example.com\n')
    mock_urlopen.return_value.__enter__.return_value = mock_response.return_value
    
    url = "https://example.com/pubkey.txt"
    pubkey = fetch_pubkey(url)
    
    assert pubkey == 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqP test@example.com'
    mock_urlopen.assert_called_once_with(url)


@patch('urllib.request.urlopen')
def test_fetch_pubkey_no_valid_key(mock_urlopen):
    """Test fetching with no valid public key in response."""
    # Mock response without valid key
    mock_response = mock_open(read_data=b'This is not a public key\nJust some random text\n')
    mock_urlopen.return_value.__enter__.return_value = mock_response.return_value
    
    url = "https://example.com/notakey.txt"
    
    with pytest.raises(ValueError, match="No valid public key found"):
        fetch_pubkey(url)


@patch('urllib.request.urlopen')
def test_fetch_pubkey_network_error(mock_urlopen):
    """Test fetching with network error.""" 
    mock_urlopen.side_effect = Exception("Network error")
    
    url = "https://example.com/pubkey.txt"
    
    with pytest.raises(ValueError, match="Failed to fetch.*Network error"):
        fetch_pubkey(url)


def test_add_signer_after_revoke():
    """Test adding signer after revocation should work."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqP test@example.com"
        
        # Add, revoke, then add again
        add_signer("test@example.com", pubkey, allowed_signers)
        revoke_signer("test@example.com", allowed_signers)
        
        # Should be able to add again after revocation
        add_signer("test@example.com", pubkey, allowed_signers)
        
        signers = list_signers(allowed_signers)
        
        # Should have both revoked and new entry
        active_signers = [s for s in signers if not s['revoked']]
        revoked_signers = [s for s in signers if s['revoked']]
        
        assert len(active_signers) == 1
        assert len(revoked_signers) == 1
        assert active_signers[0]['identity'] == "test@example.com"


def test_parse_line_with_complex_comment():
    """Test parsing line with multi-word comment."""
    line = 'user@host.com ssh-ed25519 AAAA1234 This is a multi word comment'
    parsed = parse_allowed_signers_line(line)
    
    assert parsed is not None
    assert parsed['comment'] == 'This is a multi word comment'


def test_parse_line_with_quoted_namespaces():
    """Test parsing line with quoted namespaces containing commas."""
    line = 'user@host.com namespaces="ns1,ns2,ns3" ssh-ed25519 AAAA1234 comment'
    parsed = parse_allowed_signers_line(line)
    
    assert parsed is not None
    assert parsed['namespaces'] == 'ns1,ns2,ns3'


if __name__ == "__main__":
    pytest.main([__file__])