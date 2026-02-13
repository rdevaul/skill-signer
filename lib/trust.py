#!/usr/bin/env python3
"""
Trust management for skill-signer.

Manages SSH allowed_signers files for trusted skill signers.
"""

import os
import re
import urllib.request
from pathlib import Path
from typing import List, Dict, Optional


def parse_allowed_signers_line(line: str) -> Optional[Dict]:
    """
    Parse a line from an SSH allowed_signers file.
    
    Format: identity [cert-authority] [namespaces="ns1,ns2"] keytype key [comment]
    
    Returns dict with parsed fields or None if invalid/comment.
    """
    original_line = line
    line = line.strip()
    
    # Check for revoked entries (our convention: # REVOKED: original_line)
    revoked = False
    if line.startswith('# REVOKED:'):
        revoked = True
        line = line[10:].strip()  # Remove "# REVOKED:"
    
    # Skip empty lines and regular comments (but not revoked ones)
    if not line or (line.startswith('#') and not revoked):
        return None
    
    # Split on whitespace, but preserve quoted sections
    parts = []
    in_quotes = False
    current = ""
    
    for char in line:
        if char == '"' and not in_quotes:
            in_quotes = True
            current += char
        elif char == '"' and in_quotes:
            in_quotes = False
            current += char
        elif char.isspace() and not in_quotes:
            if current:
                parts.append(current)
                current = ""
        else:
            current += char
    
    if current:
        parts.append(current)
    
    if len(parts) < 3:
        return None  # Need at least identity, keytype, key
    
    result = {
        'identity': parts[0],
        'revoked': revoked,
        'cert_authority': False,
        'namespaces': None,
        'algorithm': None,
        'key': None,
        'comment': None
    }
    
    # Parse optional fields and locate keytype/key
    key_start_idx = 1
    
    for i in range(1, len(parts)):
        part = parts[i]
        
        if part == 'cert-authority':
            result['cert_authority'] = True
            key_start_idx = i + 1
        elif part.startswith('namespaces='):
            # Extract namespaces="a,b,c"
            ns_part = part[11:]  # Remove 'namespaces='
            if ns_part.startswith('"') and ns_part.endswith('"'):
                result['namespaces'] = ns_part[1:-1]
            key_start_idx = i + 1
        elif part.startswith(('ssh-', 'ecdsa-', 'rsa-')):
            # This is the keytype
            result['algorithm'] = part
            if i + 1 < len(parts):
                result['key'] = parts[i + 1]
            
            # Everything after key is comment
            if i + 2 < len(parts):
                result['comment'] = ' '.join(parts[i + 2:])
            break
    
    return result if result['algorithm'] and result['key'] else None


def add_signer(identity: str, pubkey: str, allowed_signers_path: str):
    """
    Add a signer to the allowed_signers file.
    
    Args:
        identity: Email/identity of signer
        pubkey: Full public key line (ssh-ed25519 AAAA... comment)
        allowed_signers_path: Path to allowed_signers file
    """
    allowed_signers_path = os.path.expanduser(allowed_signers_path)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(allowed_signers_path), exist_ok=True)
    
    # Parse public key
    pubkey = pubkey.strip()
    parts = pubkey.split()
    
    if len(parts) < 2:
        raise ValueError("Invalid public key format")
    
    algorithm = parts[0]
    key = parts[1]
    comment = ' '.join(parts[2:]) if len(parts) > 2 else ""
    
    # Check if signer already exists (and is not revoked)
    if os.path.exists(allowed_signers_path):
        existing_signers = list_signers(allowed_signers_path)
        for signer in existing_signers:
            if signer['identity'] == identity and not signer['revoked']:
                raise ValueError(f"Signer {identity} already exists (not revoked)")
    
    # Format the line
    # identity namespaces="skill-manifest" algorithm key comment
    line = f'{identity} namespaces="skill-manifest" {algorithm} {key}'
    if comment:
        line += f' {comment}'
    line += '\n'
    
    # Append to file
    with open(allowed_signers_path, 'a') as f:
        f.write(line)


def revoke_signer(identity: str, allowed_signers_path: str):
    """
    Revoke a signer by commenting out their line.
    
    Args:
        identity: Email/identity to revoke
        allowed_signers_path: Path to allowed_signers file
    """
    allowed_signers_path = os.path.expanduser(allowed_signers_path)
    
    if not os.path.exists(allowed_signers_path):
        raise FileNotFoundError(f"allowed_signers not found: {allowed_signers_path}")
    
    # Read all lines
    with open(allowed_signers_path, 'r') as f:
        lines = f.readlines()
    
    # Find and revoke matching lines
    modified = False
    new_lines = []
    
    for line in lines:
        parsed = parse_allowed_signers_line(line)
        
        if parsed and parsed['identity'] == identity and not parsed['revoked']:
            # Revoke this line
            new_lines.append(f"# REVOKED: {line.strip()}\n")
            modified = True
        else:
            new_lines.append(line)
    
    if not modified:
        raise ValueError(f"No active signer found for identity: {identity}")
    
    # Write back
    with open(allowed_signers_path, 'w') as f:
        f.writelines(new_lines)


def list_signers(allowed_signers_path: str) -> List[Dict]:
    """
    List all signers from allowed_signers file.
    
    Returns list of dicts with signer information.
    """
    allowed_signers_path = os.path.expanduser(allowed_signers_path)
    
    if not os.path.exists(allowed_signers_path):
        return []
    
    signers = []
    
    with open(allowed_signers_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            parsed = parse_allowed_signers_line(line)
            if parsed:
                parsed['line_number'] = line_num
                signers.append(parsed)
    
    return signers


def fetch_pubkey(url: str) -> str:
    """
    Fetch a public key from a URL.
    
    Args:
        url: HTTP/HTTPS URL to public key file
        
    Returns:
        Public key content as string
    """
    try:
        with urllib.request.urlopen(url) as response:
            content = response.read().decode('utf-8')
        
        # Basic validation - should look like a public key
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        for line in lines:
            if line.startswith(('ssh-', 'ecdsa-', 'rsa-')):
                return line
        
        raise ValueError("No valid public key found in response")
        
    except Exception as e:
        raise ValueError(f"Failed to fetch public key from {url}: {e}")


if __name__ == "__main__":
    import tempfile
    import sys
    
    # Self-test
    print("Testing trust management...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        # Test public key (ssh-keygen -t ed25519)
        test_pubkey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKqP7Z8w3F5U9OjK8e4mFAGHh9L2M1nA0YFU4Qo7V9Ja test@example.com"
        
        # Test add
        print("  Adding signer...")
        add_signer("test@example.com", test_pubkey, allowed_signers)
        
        # Test list
        signers = list_signers(allowed_signers)
        print(f"  Listed {len(signers)} signers")
        assert len(signers) == 1
        assert signers[0]['identity'] == "test@example.com"
        assert not signers[0]['revoked']
        
        # Test revoke
        print("  Revoking signer...")
        revoke_signer("test@example.com", allowed_signers)
        
        # Test list after revoke
        signers = list_signers(allowed_signers)
        print(f"  Listed {len(signers)} signers after revoke")
        assert len(signers) == 1
        assert signers[0]['revoked']
        
        # Test duplicate add (should fail for active, but work for revoked)
        print("  Re-adding revoked signer...")
        add_signer("test@example.com", test_pubkey, allowed_signers)
        
        signers = list_signers(allowed_signers)
        active_signers = [s for s in signers if not s['revoked']]
        print(f"  Now have {len(active_signers)} active signers")
        assert len(active_signers) == 1
    
    print("✓ All trust management tests passed")