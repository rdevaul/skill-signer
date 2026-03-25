#!/usr/bin/env python3
"""
End-to-end CLI tests using subprocess.
"""

import os
import sys
import json
import tempfile
import subprocess
from pathlib import Path

import pytest

from lib.ssh_signer import check_ssh_version, generate_keypair
from lib.manifest import load_manifest


def run_cli(*args, input_text=None, expect_success=True):
    """
    Run skill-signer CLI command and return (stdout, stderr, returncode).
    """
    # Get the project root directory
    project_root = Path(__file__).parent.parent
    
    # Run CLI module directly
    cmd = [sys.executable, "-m", "lib.cli"] + list(args)
    
    result = subprocess.run(
        cmd,
        cwd=project_root,
        input=input_text,
        text=True,
        capture_output=True
    )
    
    if expect_success and result.returncode != 0:
        pytest.fail(f"Command failed: {' '.join(cmd)}\nstdout: {result.stdout}\nstderr: {result.stderr}")
    
    return result.stdout, result.stderr, result.returncode


def test_cli_help():
    """Test CLI help output."""
    stdout, stderr, code = run_cli("--help", expect_success=False)
    
    # argparse sends help to stdout and exits with 0, but our wrapper might differ
    assert code in [0, 1]  # Help can exit with 0 or 1
    help_text = stdout + stderr
    assert "skill-signer" in help_text
    assert "sign" in help_text
    assert "verify" in help_text
    assert "keygen" in help_text
    assert "trust" in help_text


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_keygen():
    """Test CLI key generation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "test_key")
        
        stdout, stderr, code = run_cli("keygen", "--output", key_path)
        
        assert code == 0
        assert "Generated" in stdout or "Generated" in stderr
        assert os.path.exists(key_path)
        assert os.path.exists(f"{key_path}.pub")


def test_cli_keygen_existing_key():
    """Test CLI key generation with existing key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "existing_key")
        
        # Create existing file
        Path(key_path).touch()
        
        stdout, stderr, code = run_cli("keygen", "--output", key_path, expect_success=False)
        
        assert code != 0
        assert "already exists" in stderr


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_sign_and_inspect():
    """Test CLI signing and inspection."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create test skill directory
        skill_dir = Path(tmpdir) / "test-skill"
        skill_dir.mkdir()
        
        (skill_dir / "SKILL.md").write_text("# Test Skill\n\nA test skill for CLI testing.")
        (skill_dir / "main.py").write_text("print('Hello from test skill')")
        (skill_dir / "data.json").write_text('{"config": "value"}')
        
        # Generate signing key
        key_path = os.path.join(tmpdir, "signing_key")
        success, _ = generate_keypair(key_path, "test-signer")
        assert success
        
        # Sign the skill
        stdout, stderr, code = run_cli(
            "sign", str(skill_dir),
            "--key", key_path,
            "--identity", "test@example.com",
            "--version", "1.2.3"
        )
        
        assert code == 0
        output = stdout + stderr
        assert "Creating manifest" in output
        assert "Signing with key" in output
        assert "Saved signed manifest" in output
        
        # Check manifest was created
        manifest_path = skill_dir / "MANIFEST.sig.json"
        assert manifest_path.exists()
        
        # Load and verify manifest structure
        manifest = load_manifest(str(manifest_path))
        assert manifest.skill_name == "Test Skill"
        assert manifest.skill_version == "1.2.3"
        assert manifest.author == "test@example.com"
        assert manifest.signature is not None
        assert manifest.signer is not None
        
        # Test inspect command
        stdout, stderr, code = run_cli("inspect", str(skill_dir))
        
        assert code == 0
        output = stdout + stderr
        assert "Test Skill" in output
        assert "1.2.3" in output
        assert "test@example.com" in output
        assert "Signed by" in output
        
        # Test verbose inspect
        stdout, stderr, code = run_cli("inspect", str(skill_dir), "--verbose")
        
        assert code == 0
        output = stdout + stderr
        assert "main.py" in output
        assert "SHA256:" in output


def test_cli_sign_missing_skill_dir():
    """Test CLI signing with missing skill directory."""
    stdout, stderr, code = run_cli(
        "sign", "/nonexistent/path",
        "--key", "/tmp/key",
        "--identity", "test@example.com",
        expect_success=False
    )
    
    assert code != 0
    assert "Not a directory" in stderr


def test_cli_sign_missing_key():
    """Test CLI signing with missing key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir) / "skill"
        skill_dir.mkdir()
        (skill_dir / "main.py").write_text("test")
        
        stdout, stderr, code = run_cli(
            "sign", str(skill_dir),
            "--key", "/nonexistent/key",
            "--identity", "test@example.com",
            expect_success=False
        )
        
        assert code != 0
        assert "Key not found" in stderr


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_trust_commands():
    """Test CLI trust management commands."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        # Generate test key
        key_path = os.path.join(tmpdir, "test_key")
        success, _ = generate_keypair(key_path, "test-key")
        assert success
        
        # Test trust add
        stdout, stderr, code = run_cli(
            "trust", "add", "test@example.com", f"{key_path}.pub",
            "--allowed-signers", allowed_signers
        )
        
        assert code == 0
        output = stdout + stderr
        assert "Added test@example.com" in output
        assert os.path.exists(allowed_signers)
        
        # Test trust list
        stdout, stderr, code = run_cli(
            "trust", "list",
            "--allowed-signers", allowed_signers
        )
        
        assert code == 0
        output = stdout + stderr
        assert "test@example.com" in output
        assert "[active]" in output
        
        # Test trust revoke
        stdout, stderr, code = run_cli(
            "trust", "revoke", "test@example.com",
            "--allowed-signers", allowed_signers
        )
        
        assert code == 0
        output = stdout + stderr
        assert "Revoked test@example.com" in output
        
        # Test list after revoke
        stdout, stderr, code = run_cli(
            "trust", "list",
            "--allowed-signers", allowed_signers
        )
        
        assert code == 0
        output = stdout + stderr
        assert "[REVOKED]" in output


def test_cli_trust_add_missing_pubkey():
    """Test CLI trust add with missing public key file."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        stdout, stderr, code = run_cli(
            "trust", "add", "test@example.com", "/nonexistent/pubkey.pub",
            "--allowed-signers", allowed_signers,
            expect_success=False
        )
        
        assert code != 0
        assert "Public key not found" in stderr


def test_cli_trust_list_empty():
    """Test CLI trust list with missing file."""
    stdout, stderr, code = run_cli(
        "trust", "list",
        "--allowed-signers", "/nonexistent/allowed_signers"
    )
    
    assert code == 0
    output = stdout + stderr
    assert "No allowed_signers file found" in output


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required") 
def test_cli_verify():
    """Test CLI verification."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create and sign a test skill
        skill_dir = Path(tmpdir) / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Test Skill")
        (skill_dir / "main.py").write_text("test")
        
        key_path = os.path.join(tmpdir, "key")
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        
        # Generate key and sign
        success, _ = generate_keypair(key_path, "test")
        assert success
        
        run_cli(
            "sign", str(skill_dir),
            "--key", key_path,
            "--identity", "test@example.com"
        )
        
        # Set up trust
        run_cli(
            "trust", "add", "test@example.com", f"{key_path}.pub",
            "--allowed-signers", allowed_signers
        )
        
        # Test verify
        stdout, stderr, code = run_cli(
            "verify", str(skill_dir),
            "--allowed-signers", allowed_signers
        )
        
        assert code == 0
        output = stdout + stderr
        assert "Test Skill" in output
        assert "test@example.com" in output
        assert "Signature is valid" in output


def test_cli_verify_missing_manifest():
    """Test CLI verification with missing manifest."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir) / "skill"
        skill_dir.mkdir()
        (skill_dir / "main.py").write_text("test")
        
        stdout, stderr, code = run_cli(
            "verify", str(skill_dir),
            "--allowed-signers", "/tmp/allowed_signers",
            expect_success=False
        )
        
        assert code != 0
        assert "No manifest found" in stderr


def test_cli_verify_missing_allowed_signers():
    """Test CLI verification with missing allowed_signers."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir) / "skill"
        skill_dir.mkdir()
        
        # Create a manifest file (even if invalid)
        (skill_dir / "MANIFEST.sig.json").write_text('{"test": "data"}')
        
        stdout, stderr, code = run_cli(
            "verify", str(skill_dir),
            "--allowed-signers", "/nonexistent/allowed_signers",
            expect_success=False
        )
        
        assert code != 0
        assert "allowed_signers not found" in stderr


def test_cli_inspect_missing_manifest():
    """Test CLI inspect with missing manifest."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir) / "skill"
        skill_dir.mkdir()
        (skill_dir / "main.py").write_text("test")
        
        stdout, stderr, code = run_cli("inspect", str(skill_dir), expect_success=False)
        
        assert code != 0
        assert "No manifest found" in stderr


def test_cli_no_command():
    """Test CLI with no command shows help."""
    stdout, stderr, code = run_cli(expect_success=False)
    
    assert code != 0
    help_text = stdout + stderr
    assert "skill-signer" in help_text


def test_cli_trust_no_subcommand():
    """Test CLI trust with no subcommand shows help."""
    stdout, stderr, code = run_cli("trust", expect_success=False)
    
    assert code != 0
    help_text = stdout + stderr
    assert "trust" in help_text



# ---------------------------------------------------------------------------
# New tests for UX improvements: Fix 1–4
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_keygen_with_name():
    """Fix 1 – keygen accepts --name flag and creates the key."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "named_key")

        stdout, stderr, code = run_cli("keygen", "--output", key_path, "--name", "signer@example.com")

        assert code == 0
        assert os.path.exists(key_path)
        assert os.path.exists(f"{key_path}.pub")


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_keygen_creates_meta_file():
    """Fix 3 – keygen writes a .meta sidecar with the identity and a created timestamp."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "meta_key")

        stdout, stderr, code = run_cli("keygen", "--output", key_path, "--name", "meta@example.com")

        assert code == 0
        meta_path = f"{key_path}.meta"
        assert os.path.exists(meta_path), f".meta sidecar not found at {meta_path}"

        with open(meta_path, "r") as f:
            meta = json.load(f)

        assert meta.get("identity") == "meta@example.com"
        assert "created" in meta
        output = stdout + stderr
        assert "Meta file" in output


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_keygen_comment_alias():
    """Fix 1 – --comment still works as a hidden backward-compat alias."""
    with tempfile.TemporaryDirectory() as tmpdir:
        key_path = os.path.join(tmpdir, "compat_key")

        # --comment is a hidden alias; it should still succeed and write the meta
        stdout, stderr, code = run_cli("keygen", "--output", key_path, "--comment", "compat@example.com")

        assert code == 0
        meta_path = f"{key_path}.meta"
        with open(meta_path, "r") as f:
            meta = json.load(f)
        assert meta.get("identity") == "compat@example.com"


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_sign_uses_meta_file():
    """Fix 3 – sign reads identity from the .meta sidecar when --identity is omitted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir) / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Test Skill")
        (skill_dir / "main.py").write_text("print('hello')")

        key_path = os.path.join(tmpdir, "signing_key")

        # keygen via CLI creates the .meta sidecar
        run_cli("keygen", "--output", key_path, "--name", "MetaIdentity@example.com")

        # sign WITHOUT --identity flag; should auto-discover from .meta
        stdout, stderr, code = run_cli(
            "sign", str(skill_dir),
            "--key", key_path,
            # intentionally omitting --identity
        )

        assert code == 0
        output = stdout + stderr
        # Identity must have been lowercased
        assert "metaidentity@example.com" in output

        # Manifest should record the lowercased identity
        manifest = load_manifest(str(skill_dir / "MANIFEST.sig.json"))
        assert manifest.author == "metaidentity@example.com"
        assert manifest.signer.identity == "metaidentity@example.com"


def test_cli_sign_missing_identity_no_meta():
    """Fix 3 – sign without --identity and no .meta file gives a helpful error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir) / "skill"
        skill_dir.mkdir()
        (skill_dir / "main.py").write_text("test")

        # Write a bare key file (no .meta)
        key_path = os.path.join(tmpdir, "bare_key")
        Path(key_path).write_text("not-a-real-key")

        stdout, stderr, code = run_cli(
            "sign", str(skill_dir),
            "--key", key_path,
            expect_success=False,
        )

        assert code != 0
        assert "identity" in stderr.lower() or "identity" in stdout.lower()


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_trust_add_identity_from_pubkey():
    """Fix 2 – trust add without identity arg reads it from the key comment."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        key_path = os.path.join(tmpdir, "test_key")

        # Generate with a recognisable comment that will become the identity
        success, _ = generate_keypair(key_path, "autoident@example.com")
        assert success

        # Omit the identity positional – only pass the pubkey
        stdout, stderr, code = run_cli(
            "trust", "add", f"{key_path}.pub",
            "--allowed-signers", allowed_signers,
        )

        assert code == 0
        output = stdout + stderr
        # Identity parsed from comment; should be lowercased
        assert "autoident@example.com" in output
        assert os.path.exists(allowed_signers)

        # Verify the entry in the file uses the lowercased identity
        from lib.trust import list_signers
        signers = list_signers(allowed_signers)
        assert any(s["identity"] == "autoident@example.com" for s in signers)


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_trust_add_no_identity_no_comment():
    """Fix 2 – trust add without identity and a key with no comment gives a helpful error."""
    with tempfile.TemporaryDirectory() as tmpdir:
        allowed_signers = os.path.join(tmpdir, "allowed_signers")
        # Create a pubkey file that has no comment field
        pubkey_path = os.path.join(tmpdir, "nocomment.pub")
        Path(pubkey_path).write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n")

        stdout, stderr, code = run_cli(
            "trust", "add", pubkey_path,
            "--allowed-signers", allowed_signers,
            expect_success=False,
        )

        assert code != 0
        assert "identity" in stderr.lower() or "identity" in stdout.lower()


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_case_normalization():
    """Fix 4 – uppercase identity is normalized to lowercase end-to-end (sign→verify)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        skill_dir = Path(tmpdir) / "case-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Case Skill")
        (skill_dir / "main.py").write_text("test")

        key_path = os.path.join(tmpdir, "key")
        allowed_signers = os.path.join(tmpdir, "allowed_signers")

        success, _ = generate_keypair(key_path, "Case@Example.COM")
        assert success

        # Sign with a MIXED-CASE identity
        run_cli(
            "sign", str(skill_dir),
            "--key", key_path,
            "--identity", "Case@Example.COM",
            "--version", "0.1.0",
        )

        # Trust add with the same mixed-case identity (should be stored lowercased)
        run_cli(
            "trust", "add", "Case@Example.COM", f"{key_path}.pub",
            "--allowed-signers", allowed_signers,
        )

        # Verify – the manifest stores the lowercased identity; verify should pass
        stdout, stderr, code = run_cli(
            "verify", str(skill_dir),
            "--allowed-signers", allowed_signers,
        )

        assert code == 0
        assert "Signature is valid" in stdout + stderr

        # Also confirm the stored identity in the manifest is lowercased
        manifest = load_manifest(str(skill_dir / "MANIFEST.sig.json"))
        assert manifest.author == "case@example.com"
        assert manifest.signer.identity == "case@example.com"


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_verify_file_hashes_unmodified():
    """Test that verify passes when all files are unmodified."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create and sign a test skill
        skill_dir = Path(tmpdir) / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Test Skill")
        (skill_dir / "main.py").write_text("print('hello')")
        (skill_dir / "data.json").write_text('{"key": "value"}')

        key_path = os.path.join(tmpdir, "key")
        allowed_signers = os.path.join(tmpdir, "allowed_signers")

        # Generate key and sign
        success, _ = generate_keypair(key_path, "test")
        assert success

        run_cli(
            "sign", str(skill_dir),
            "--key", key_path,
            "--identity", "test@example.com"
        )

        # Set up trust
        run_cli(
            "trust", "add", "test@example.com", f"{key_path}.pub",
            "--allowed-signers", allowed_signers
        )

        # Verify should pass with unmodified files
        stdout, stderr, code = run_cli(
            "verify", str(skill_dir),
            "--allowed-signers", allowed_signers
        )

        assert code == 0
        output = stdout + stderr
        assert "Signature is valid" in output
        assert "All" in output and "files verified" in output


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_verify_file_modified():
    """Test that verify fails when a file is modified after signing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create and sign a test skill
        skill_dir = Path(tmpdir) / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Test Skill")
        (skill_dir / "main.py").write_text("print('hello')")

        key_path = os.path.join(tmpdir, "key")
        allowed_signers = os.path.join(tmpdir, "allowed_signers")

        # Generate key and sign
        success, _ = generate_keypair(key_path, "test")
        assert success

        run_cli(
            "sign", str(skill_dir),
            "--key", key_path,
            "--identity", "test@example.com"
        )

        # Set up trust
        run_cli(
            "trust", "add", "test@example.com", f"{key_path}.pub",
            "--allowed-signers", allowed_signers
        )

        # Modify a file after signing
        (skill_dir / "main.py").write_text("print('modified')")

        # Verify should fail
        stdout, stderr, code = run_cli(
            "verify", str(skill_dir),
            "--allowed-signers", allowed_signers,
            expect_success=False
        )

        assert code != 0
        output = stdout + stderr
        assert "Modified files" in output
        assert "main.py" in output


@pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")
def test_cli_verify_file_missing():
    """Test that verify fails when a file is removed after signing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create and sign a test skill
        skill_dir = Path(tmpdir) / "test-skill"
        skill_dir.mkdir()
        (skill_dir / "SKILL.md").write_text("# Test Skill")
        (skill_dir / "main.py").write_text("print('hello')")
        (skill_dir / "data.json").write_text('{"key": "value"}')

        key_path = os.path.join(tmpdir, "key")
        allowed_signers = os.path.join(tmpdir, "allowed_signers")

        # Generate key and sign
        success, _ = generate_keypair(key_path, "test")
        assert success

        run_cli(
            "sign", str(skill_dir),
            "--key", key_path,
            "--identity", "test@example.com"
        )

        # Set up trust
        run_cli(
            "trust", "add", "test@example.com", f"{key_path}.pub",
            "--allowed-signers", allowed_signers
        )

        # Remove a file after signing
        (skill_dir / "data.json").unlink()

        # Verify should fail
        stdout, stderr, code = run_cli(
            "verify", str(skill_dir),
            "--allowed-signers", allowed_signers,
            expect_success=False
        )

        assert code != 0
        output = stdout + stderr
        assert "Missing files" in output
        assert "data.json" in output


if __name__ == "__main__":
    pytest.main([__file__])
