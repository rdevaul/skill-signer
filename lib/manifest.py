#!/usr/bin/env python3
"""
Skill manifest generation and parsing.

Creates MANIFEST.sig.json with file hashes, metadata, and signatures.
"""

import os
import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

from .ssh_signer import sign_data, get_key_fingerprint


@dataclass
class FileEntry:
    """A file in the manifest."""
    sha256: str
    size: int


@dataclass
class Dependency:
    """A skill dependency."""
    name: str
    version: str
    signer: Optional[str] = None
    manifest_hash: Optional[str] = None


@dataclass
class SignerInfo:
    """Information about the signer."""
    identity: str
    key_fingerprint: str
    algorithm: str = "ssh-ed25519"


@dataclass
class SkillManifest:
    """Complete skill manifest."""
    version: str
    skill_name: str
    skill_version: str
    author: str
    files: Dict[str, FileEntry]
    dependencies: List[Dependency]
    timestamp: str
    signer: Optional[SignerInfo] = None
    signature: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result = {
            "version": self.version,
            "skill": {
                "name": self.skill_name,
                "version": self.skill_version,
                "author": self.author
            },
            "files": {
                name: {"sha256": entry.sha256, "size": entry.size}
                for name, entry in self.files.items()
            },
            "dependencies": [
                {k: v for k, v in asdict(dep).items() if v is not None}
                for dep in self.dependencies
            ],
            "timestamp": self.timestamp
        }
        
        if self.signer:
            result["signer"] = asdict(self.signer)
        if self.signature:
            result["signature"] = self.signature
            
        return result
    
    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)
    
    def signing_payload(self) -> bytes:
        """Get bytes to sign (manifest without signature field)."""
        d = self.to_dict()
        d.pop("signature", None)
        return json.dumps(d, sort_keys=True, separators=(',', ':')).encode('utf-8')


def hash_file(path: Path) -> FileEntry:
    """Calculate SHA256 hash and size of a file."""
    sha256 = hashlib.sha256()
    size = 0
    
    with open(path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
            size += len(chunk)
    
    return FileEntry(sha256=sha256.hexdigest(), size=size)


def should_include_file(path: Path, name: str) -> bool:
    """Determine if a file should be included in the manifest."""
    # Skip hidden files and directories
    if name.startswith('.'):
        return False
    
    # Skip common non-essential files
    skip_patterns = [
        '__pycache__',
        '*.pyc',
        '*.pyo',
        'node_modules',
        '.git',
        '.DS_Store',
        'MANIFEST.sig.json',  # Don't include ourselves
    ]
    
    for pattern in skip_patterns:
        if pattern.startswith('*'):
            if name.endswith(pattern[1:]):
                return False
        elif name == pattern:
            return False
    
    return True


def scan_skill_directory(skill_path: Path) -> Dict[str, FileEntry]:
    """
    Scan a skill directory and hash all relevant files.
    
    Returns dict mapping relative paths to FileEntry objects.
    """
    files = {}
    skill_path = Path(skill_path).resolve()
    
    for root, dirs, filenames in os.walk(skill_path):
        # Filter directories in-place
        dirs[:] = [d for d in dirs if should_include_file(Path(root) / d, d)]
        
        for filename in filenames:
            if not should_include_file(Path(root) / filename, filename):
                continue
                
            full_path = Path(root) / filename
            rel_path = full_path.relative_to(skill_path)
            
            files[str(rel_path)] = hash_file(full_path)
    
    return files


def parse_skill_metadata(skill_path: Path) -> Dict[str, str]:
    """
    Extract skill metadata from SKILL.md or similar.
    
    Looks for YAML frontmatter or first heading.
    """
    skill_md = skill_path / "SKILL.md"
    
    metadata = {
        "name": skill_path.name,
        "version": "0.0.0",
        "author": "unknown"
    }
    
    if skill_md.exists():
        content = skill_md.read_text()
        
        # Try to find name from first heading
        for line in content.split('\n'):
            if line.startswith('# '):
                metadata["name"] = line[2:].strip()
                break
    
    return metadata


def create_manifest(
    skill_path: str,
    author: str,
    version: Optional[str] = None,
    dependencies: Optional[List[Dict]] = None
) -> SkillManifest:
    """
    Create an unsigned manifest for a skill directory.
    
    Args:
        skill_path: Path to skill directory
        author: Author email/identity
        version: Skill version (auto-detected if not provided)
        dependencies: List of dependency dicts
        
    Returns:
        Unsigned SkillManifest
    """
    skill_path = Path(skill_path).resolve()
    
    if not skill_path.is_dir():
        raise ValueError(f"Not a directory: {skill_path}")
    
    # Get metadata
    metadata = parse_skill_metadata(skill_path)
    if version:
        metadata["version"] = version
    
    # Scan files
    files = scan_skill_directory(skill_path)
    
    # Parse dependencies
    deps = []
    if dependencies:
        for dep in dependencies:
            deps.append(Dependency(**dep))
    
    return SkillManifest(
        version="1.0.0",
        skill_name=metadata["name"],
        skill_version=metadata["version"],
        author=author,
        files=files,
        dependencies=deps,
        timestamp=datetime.now(timezone.utc).isoformat()
    )


def sign_manifest(
    manifest: SkillManifest,
    key_path: str,
    identity: str
) -> SkillManifest:
    """
    Sign a manifest with an SSH key.
    
    Args:
        manifest: Unsigned manifest
        key_path: Path to SSH private key
        identity: Signer email/identity
        
    Returns:
        Signed manifest with signature field populated
    """
    from .ssh_signer import sign_data, get_key_fingerprint
    
    # Get key fingerprint
    fingerprint = get_key_fingerprint(os.path.expanduser(key_path))
    if not fingerprint:
        raise ValueError(f"Could not get fingerprint for key: {key_path}")
    
    # Set signer info
    manifest.signer = SignerInfo(
        identity=identity,
        key_fingerprint=fingerprint,
        algorithm="ssh-ed25519"
    )
    
    # Sign the payload
    payload = manifest.signing_payload()
    result = sign_data(payload, key_path)
    
    if not result.success:
        raise ValueError(f"Signing failed: {result.error}")
    
    manifest.signature = result.signature
    return manifest


def save_manifest(manifest: SkillManifest, skill_path: str) -> Path:
    """
    Save manifest to MANIFEST.sig.json in the skill directory.
    
    Returns path to saved manifest.
    """
    output_path = Path(skill_path) / "MANIFEST.sig.json"
    output_path.write_text(manifest.to_json())
    return output_path


def load_manifest(manifest_path: str) -> SkillManifest:
    """Load a manifest from JSON file."""
    with open(manifest_path, 'r') as f:
        data = json.load(f)
    
    files = {
        name: FileEntry(**entry)
        for name, entry in data.get("files", {}).items()
    }
    
    deps = [
        Dependency(**dep)
        for dep in data.get("dependencies", [])
    ]
    
    signer = None
    if "signer" in data:
        signer = SignerInfo(**data["signer"])
    
    return SkillManifest(
        version=data["version"],
        skill_name=data["skill"]["name"],
        skill_version=data["skill"]["version"],
        author=data["skill"]["author"],
        files=files,
        dependencies=deps,
        timestamp=data["timestamp"],
        signer=signer,
        signature=data.get("signature")
    )


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python manifest.py <skill-directory>")
        sys.exit(1)
    
    skill_dir = sys.argv[1]
    print(f"Scanning {skill_dir}...")
    
    manifest = create_manifest(
        skill_dir,
        author="test@example.com",
        version="1.0.0"
    )
    
    print(f"\nManifest for: {manifest.skill_name} v{manifest.skill_version}")
    print(f"Files: {len(manifest.files)}")
    for path, entry in manifest.files.items():
        print(f"  {path}: {entry.sha256[:16]}... ({entry.size} bytes)")
    
    print(f"\nJSON output:")
    print(manifest.to_json())
