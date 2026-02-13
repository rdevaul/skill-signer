#!/usr/bin/env python3
"""
Tests for manifest creation, hashing, and serialization.
"""

import os
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone

import pytest

from lib.manifest import (
    SkillManifest,
    FileEntry,
    Dependency,
    SignerInfo,
    create_manifest,
    sign_manifest,
    save_manifest,
    load_manifest,
    hash_file,
    should_include_file,
    scan_skill_directory,
    parse_skill_metadata,
)


def test_file_entry():
    """Test FileEntry dataclass."""
    entry = FileEntry(sha256="abc123", size=42)
    assert entry.sha256 == "abc123"
    assert entry.size == 42


def test_dependency():
    """Test Dependency dataclass."""
    dep = Dependency(name="test-skill", version="1.0.0", signer="test@example.com")
    assert dep.name == "test-skill"
    assert dep.version == "1.0.0"
    assert dep.signer == "test@example.com"


def test_signer_info():
    """Test SignerInfo dataclass."""
    signer = SignerInfo(
        identity="test@example.com",
        key_fingerprint="SHA256:abc123...",
        algorithm="ssh-ed25519"
    )
    assert signer.identity == "test@example.com"
    assert signer.algorithm == "ssh-ed25519"


def test_skill_manifest_serialization():
    """Test manifest serialization to/from dict/JSON."""
    files = {"test.py": FileEntry(sha256="abc123", size=42)}
    deps = [Dependency(name="dep1", version="1.0.0")]
    
    manifest = SkillManifest(
        version="1.0.0",
        skill_name="test-skill",
        skill_version="0.1.0",
        author="test@example.com",
        files=files,
        dependencies=deps,
        timestamp=datetime.now(timezone.utc).isoformat()
    )
    
    # Test to_dict
    d = manifest.to_dict()
    assert d["version"] == "1.0.0"
    assert d["skill"]["name"] == "test-skill"
    assert d["files"]["test.py"]["sha256"] == "abc123"
    assert len(d["dependencies"]) == 1
    
    # Test to_json
    json_str = manifest.to_json()
    assert "test-skill" in json_str
    
    # Test JSON is valid
    parsed = json.loads(json_str)
    assert parsed["skill"]["name"] == "test-skill"


def test_manifest_signing_payload():
    """Test signing payload generation."""
    manifest = SkillManifest(
        version="1.0.0",
        skill_name="test",
        skill_version="1.0.0", 
        author="test@example.com",
        files={},
        dependencies=[],
        timestamp="2024-01-01T00:00:00Z",
        signature="should-be-removed"
    )
    
    payload = manifest.signing_payload()
    
    # Should be JSON bytes without signature field
    parsed = json.loads(payload.decode())
    assert "signature" not in parsed
    assert parsed["skill"]["name"] == "test"


def test_hash_file():
    """Test file hashing."""
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as tmp:
        tmp.write("hello world")
        tmp_path = tmp.name
    
    try:
        entry = hash_file(Path(tmp_path))
        
        # SHA256 of "hello world"
        expected_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert entry.sha256 == expected_hash
        assert entry.size == 11
    finally:
        os.unlink(tmp_path)


def test_should_include_file():
    """Test file inclusion logic."""
    # Should include
    assert should_include_file(Path("/tmp/test.py"), "test.py")
    assert should_include_file(Path("/tmp/SKILL.md"), "SKILL.md")
    assert should_include_file(Path("/tmp/data.json"), "data.json")
    
    # Should exclude
    assert not should_include_file(Path("/tmp/.hidden"), ".hidden")
    assert not should_include_file(Path("/tmp/.git"), ".git") 
    assert not should_include_file(Path("/tmp/test.pyc"), "test.pyc")
    assert not should_include_file(Path("/tmp/__pycache__"), "__pycache__")
    assert not should_include_file(Path("/tmp/MANIFEST.sig.json"), "MANIFEST.sig.json")


def test_scan_skill_directory():
    """Test directory scanning."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir)
        
        # Create test files
        (skill_dir / "SKILL.md").write_text("# Test Skill\n\nA test skill.")
        (skill_dir / "main.py").write_text("print('hello')")
        (skill_dir / "data.json").write_text('{"key": "value"}')
        
        # Create files that should be excluded
        (skill_dir / ".hidden").write_text("hidden")
        (skill_dir / "__pycache__").mkdir()
        (skill_dir / "__pycache__" / "main.pyc").write_text("bytecode")
        
        files = scan_skill_directory(skill_dir)
        
        # Should have included files
        assert "SKILL.md" in files
        assert "main.py" in files 
        assert "data.json" in files
        
        # Should have excluded files
        assert ".hidden" not in files
        assert "__pycache__/main.pyc" not in files
        
        # Check hash values
        assert files["main.py"].sha256 is not None
        assert files["main.py"].size == 14  # len("print('hello')")


def test_parse_skill_metadata():
    """Test skill metadata parsing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir)
        
        # Test with SKILL.md
        skill_md = skill_dir / "SKILL.md"
        skill_md.write_text("# My Awesome Skill\n\nThis is a test skill.")
        
        metadata = parse_skill_metadata(skill_dir)
        assert metadata["name"] == "My Awesome Skill"
        assert metadata["version"] == "0.0.0"  # default
        assert metadata["author"] == "unknown"  # default
        
        # Test without SKILL.md (fallback to directory name)
        skill_md.unlink()
        metadata = parse_skill_metadata(skill_dir)
        assert metadata["name"] == skill_dir.name


def test_create_manifest():
    """Test manifest creation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir)
        
        # Create test skill
        (skill_dir / "SKILL.md").write_text("# Test Skill")
        (skill_dir / "main.py").write_text("print('test')")
        
        manifest = create_manifest(
            str(skill_dir),
            author="test@example.com",
            version="1.2.3"
        )
        
        assert manifest.skill_name == "Test Skill"
        assert manifest.skill_version == "1.2.3"
        assert manifest.author == "test@example.com"
        assert "main.py" in manifest.files
        assert "SKILL.md" in manifest.files
        assert manifest.signature is None  # unsigned


def test_save_and_load_manifest():
    """Test manifest saving and loading."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir)
        
        # Create test manifest
        manifest = SkillManifest(
            version="1.0.0",
            skill_name="test-skill",
            skill_version="0.1.0",
            author="test@example.com",
            files={"test.py": FileEntry(sha256="abc123", size=42)},
            dependencies=[],
            timestamp="2024-01-01T00:00:00Z"
        )
        
        # Save manifest
        output_path = save_manifest(manifest, str(skill_dir))
        expected_path = skill_dir / "MANIFEST.sig.json"
        assert output_path == expected_path
        assert expected_path.exists()
        
        # Load manifest
        loaded = load_manifest(str(expected_path))
        
        assert loaded.skill_name == manifest.skill_name
        assert loaded.skill_version == manifest.skill_version
        assert loaded.author == manifest.author
        assert "test.py" in loaded.files
        assert loaded.files["test.py"].sha256 == "abc123"


def test_create_manifest_invalid_directory():
    """Test manifest creation with invalid directory."""
    with pytest.raises(ValueError, match="Not a directory"):
        create_manifest("/nonexistent/path", author="test@example.com")


def test_manifest_with_dependencies():
    """Test manifest with dependencies."""
    deps = [
        {"name": "skill-a", "version": "1.0.0", "signer": "dev@example.com"},
        {"name": "skill-b", "version": "2.1.0"}
    ]
    
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir)
        (skill_dir / "main.py").write_text("test")
        
        manifest = create_manifest(
            str(skill_dir),
            author="test@example.com",
            dependencies=deps
        )
        
        assert len(manifest.dependencies) == 2
        assert manifest.dependencies[0].name == "skill-a"
        assert manifest.dependencies[0].signer == "dev@example.com"
        assert manifest.dependencies[1].name == "skill-b"
        assert manifest.dependencies[1].signer is None


if __name__ == "__main__":
    pytest.main([__file__])