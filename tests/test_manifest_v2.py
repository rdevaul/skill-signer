#!/usr/bin/env python3
"""
Tests for manifest version 2: MANIFEST.json and a detached OpenSSH signature.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lib import check_ssh_version, generate_keypair
from lib import manifest_v2
from lib.manifest_v2 import ManifestError, Requires

pytestmark = pytest.mark.skipif(not check_ssh_version()[0], reason="OpenSSH 8.0+ required")

IDENTITY = "alice@example.com"


def run_cli(*args):
    result = subprocess.run(
        [sys.executable, "-m", "lib.cli", *args],
        capture_output=True, text=True,
        cwd=os.path.join(os.path.dirname(__file__), '..'),
    )
    return result.stdout + result.stderr, result.returncode


def make_key(tmp_path, name="key"):
    key = str(tmp_path / name)
    ok, message = generate_keypair(key, name)
    assert ok, message
    return key


def trust(tmp_path, *entries):
    """Write an allowed_signers file from (identity, key path) pairs."""
    path = tmp_path / "allowed_signers"
    lines = []
    for identity, key in entries:
        pubkey = Path(key + ".pub").read_text().strip()
        lines.append(f'{identity} namespaces="skill-manifest" {pubkey}\n')
    path.write_text("".join(lines))
    return str(path)


@pytest.fixture
def skill(tmp_path):
    d = tmp_path / "demo-skill"
    (d / "scripts").mkdir(parents=True)
    (d / "SKILL.md").write_text(
        "---\nname: demo-skill\ndescription: Does a demonstration.\n---\n# Demo\n"
    )
    (d / "scripts" / "run.py").write_text("print('hi')\n")
    (d / ".hidden").write_text("dotfiles are signed too\n")
    return d


@pytest.fixture
def signed(tmp_path, skill):
    key = make_key(tmp_path)
    manifest = manifest_v2.build_manifest(skill, version="1.0.0", scripts=["scripts/run.py"])
    manifest_hash = manifest_v2.sign_skill(skill, manifest, key)
    return skill, key, trust(tmp_path, (IDENTITY, key)), manifest_hash


def rewrite_manifest(skill, change):
    """Edit MANIFEST.json's document in place (which breaks its signature)."""
    path = skill / "MANIFEST.json"
    doc = json.loads(path.read_text())
    change(doc)
    path.write_text(json.dumps(doc, indent=2) + "\n")


def resign_raw(skill, key):
    """Sign MANIFEST.json as it is with stock ssh-keygen."""
    sig = skill / "MANIFEST.json.sig"
    if sig.exists():
        sig.unlink()
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-n", "skill-manifest", "-f", key, str(skill / "MANIFEST.json")],
        check=True, capture_output=True,
    )


# ---------------------------------------------------------------- writing

def test_sign_writes_both_files_and_lists_every_file(signed):
    skill, _, _, manifest_hash = signed
    data = (skill / "MANIFEST.json").read_bytes()
    doc = json.loads(data)
    assert doc["manifest_version"] == 2
    assert doc["name"] == "demo-skill"
    assert doc["version"] == "1.0.0"
    assert doc["description"] == "Does a demonstration."
    assert sorted(doc["files"]) == [".hidden", "SKILL.md", "scripts/run.py"]
    assert doc["scripts"] == ["scripts/run.py"]
    assert doc["requires"] == {"network": "none", "secrets": [], "read_only": []}
    assert "signer" not in doc and "signature" not in doc and "author" not in doc
    assert manifest_hash == hashlib.sha256(data).hexdigest()
    entry = doc["files"]["scripts/run.py"]
    assert entry == {
        "sha256": hashlib.sha256(b"print('hi')\n").hexdigest(),
        "size": len(b"print('hi')\n"),
    }
    assert (skill / "MANIFEST.json.sig").read_text().startswith("-----BEGIN SSH SIGNATURE-----")


def test_stock_ssh_keygen_verifies_what_sign_writes(signed):
    skill, _, allowed, _ = signed
    with open(skill / "MANIFEST.json", "rb") as manifest:
        result = subprocess.run(
            ["ssh-keygen", "-Y", "verify", "-f", allowed, "-I", IDENTITY,
             "-n", "skill-manifest", "-s", str(skill / "MANIFEST.json.sig")],
            stdin=manifest, capture_output=True, text=True,
        )
    assert result.returncode == 0, result.stderr


def test_a_skill_signed_with_stock_ssh_keygen_verifies(tmp_path, skill):
    key = make_key(tmp_path)
    manifest = manifest_v2.build_manifest(skill)
    (skill / "MANIFEST.json").write_bytes(manifest.to_bytes())
    resign_raw(skill, key)
    verified = manifest_v2.verify_skill(skill, trust(tmp_path, (IDENTITY, key)))
    assert verified.signer == IDENTITY


def test_non_ascii_is_stored_as_written_and_verifies(tmp_path, skill):
    key = make_key(tmp_path)
    (skill / "données.txt").write_text("x")
    manifest = manifest_v2.build_manifest(skill, description="Crée des pièces — vite.")
    manifest_v2.sign_skill(skill, manifest, key)
    data = (skill / "MANIFEST.json").read_bytes()
    assert "Crée des pièces — vite.".encode("utf-8") in data
    assert "données.txt".encode("utf-8") in data
    manifest_v2.verify_skill(skill, trust(tmp_path, (IDENTITY, key)))


def test_signing_again_keeps_declared_fields(signed):
    skill, key, allowed, first_hash = signed
    (skill / "notes.txt").write_text("new file\n")
    manifest = manifest_v2.build_manifest(skill)
    assert manifest.version == "1.0.0"
    assert manifest.scripts == ["scripts/run.py"]
    second_hash = manifest_v2.sign_skill(skill, manifest, key)
    assert second_hash != first_hash
    assert "notes.txt" in manifest_v2.verify_skill(skill, allowed).manifest.files


def test_build_refuses_a_symlink(tmp_path, skill):
    (tmp_path / "outside.txt").write_text("secret")
    os.symlink(tmp_path / "outside.txt", skill / "link.txt")
    with pytest.raises(ManifestError, match="symbolic links"):
        manifest_v2.build_manifest(skill)


def test_build_refuses_a_symlinked_directory(tmp_path, skill):
    (tmp_path / "elsewhere").mkdir()
    os.symlink(tmp_path / "elsewhere", skill / "linked-dir")
    with pytest.raises(ManifestError, match="symbolic links"):
        manifest_v2.build_manifest(skill)


def test_build_refuses_a_fifo(skill):
    os.mkfifo(skill / "pipe")
    with pytest.raises(ManifestError, match="not a regular file"):
        manifest_v2.build_manifest(skill)


@pytest.mark.parametrize("name", ["Demo", "1skill", "has space", "", "a" * 65, "naïve"])
def test_build_refuses_a_bad_name(skill, name):
    with pytest.raises(ManifestError, match="invalid skill name"):
        manifest_v2.build_manifest(skill, name=name)


def test_build_needs_a_description(tmp_path):
    d = tmp_path / "bare"
    d.mkdir()
    (d / "SKILL.md").write_text("# Bare\n")
    with pytest.raises(ManifestError, match="needs a description"):
        manifest_v2.build_manifest(d)
    with pytest.raises(ManifestError, match="limit is 500"):
        manifest_v2.build_manifest(d, description="x" * 501)


def test_build_refuses_a_script_that_is_not_a_file(skill):
    with pytest.raises(ManifestError, match="not a file in the skill"):
        manifest_v2.build_manifest(skill, scripts=["scripts/missing.py"])


def test_build_refuses_paths_that_differ_only_by_case(skill):
    (skill / "readme.txt").write_text("a")
    (skill / "README.txt").write_text("b")
    if len(list(skill.glob("[rR][eE][aA][dD][mM][eE].txt"))) < 2:
        pytest.skip("case-insensitive file system")
    with pytest.raises(ManifestError, match="letter case"):
        manifest_v2.build_manifest(skill)


def test_build_refuses_too_many_files(skill):
    for i in range(manifest_v2.MAX_FILES):
        (skill / f"f{i}").write_text("")
    with pytest.raises(ManifestError, match="at most 512 files"):
        manifest_v2.build_manifest(skill)


def test_clutter_is_listed_and_reported(skill):
    (skill / "__pycache__").mkdir()
    (skill / "__pycache__" / "x.pyc").write_bytes(b"\0")
    manifest = manifest_v2.build_manifest(skill)
    assert "__pycache__/x.pyc" in manifest.files
    assert manifest_v2.find_clutter(manifest.files) == ["__pycache__/x.pyc"]


# ------------------------------------------------------------- verifying

def test_verify_accepts_a_signed_skill(signed):
    skill, _, allowed, manifest_hash = signed
    verified = manifest_v2.verify_skill(skill, allowed)
    assert verified.signer == IDENTITY
    assert verified.manifest_sha256 == manifest_hash
    assert verified.manifest.scripts == ["scripts/run.py"]


def test_the_signer_comes_from_the_key_not_the_manifest(tmp_path, signed):
    skill, key, _, _ = signed
    allowed = trust(tmp_path, ("someone-else@example.com", make_key(tmp_path, "other")),
                    ("bob@example.com", key))
    assert manifest_v2.verify_skill(skill, allowed).signer == "bob@example.com"
    with pytest.raises(ManifestError, match="not by carol@example.com"):
        manifest_v2.verify_skill(skill, allowed, identity="carol@example.com")


def test_verify_refuses_an_untrusted_key(tmp_path, signed):
    skill, _, _, _ = signed
    allowed = trust(tmp_path, (IDENTITY, make_key(tmp_path, "other")))
    with pytest.raises(ManifestError, match="does not belong to any trusted signer"):
        manifest_v2.verify_skill(skill, allowed)


def test_verify_refuses_a_signature_from_another_namespace(tmp_path, signed):
    skill, key, allowed, _ = signed
    (skill / "MANIFEST.json.sig").unlink()
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-n", "file", "-f", key, str(skill / "MANIFEST.json")],
        check=True, capture_output=True,
    )
    with pytest.raises(ManifestError, match="signature verification failed"):
        manifest_v2.verify_skill(skill, allowed)


def test_verify_refuses_a_key_trusted_for_another_namespace(tmp_path, signed):
    skill, key, _, _ = signed
    allowed = tmp_path / "allowed_signers"
    allowed.write_text(f'{IDENTITY} namespaces="git" {Path(key + ".pub").read_text()}')
    with pytest.raises(ManifestError):
        manifest_v2.verify_skill(skill, str(allowed))


def test_verify_refuses_an_edited_manifest(signed):
    skill, _, allowed, _ = signed
    path = skill / "MANIFEST.json"
    path.write_bytes(path.read_bytes().replace(b'"1.0.0"', b'"1.0.1"'))
    with pytest.raises(ManifestError, match="signature verification failed"):
        manifest_v2.verify_skill(skill, allowed)


def test_verify_refuses_a_reformatted_manifest(signed):
    """The signature is over the stored bytes, not over the JSON value."""
    skill, _, allowed, _ = signed
    path = skill / "MANIFEST.json"
    path.write_text(json.dumps(json.loads(path.read_text())))
    with pytest.raises(ManifestError, match="signature verification failed"):
        manifest_v2.verify_skill(skill, allowed)


def test_verify_refuses_a_changed_file(signed):
    skill, _, allowed, _ = signed
    (skill / "scripts" / "run.py").write_text("print('ho')\n")
    with pytest.raises(ManifestError, match="does not match the manifest: scripts/run.py"):
        manifest_v2.verify_skill(skill, allowed)


def test_verify_refuses_a_missing_file(signed):
    skill, _, allowed, _ = signed
    (skill / ".hidden").unlink()
    with pytest.raises(ManifestError, match="listed file is missing: .hidden"):
        manifest_v2.verify_skill(skill, allowed)


@pytest.mark.parametrize("extra", [".env", "__pycache__/x.pyc", "node_modules/m/index.js", "extra.txt"])
def test_verify_refuses_an_unlisted_file(signed, extra):
    skill, _, allowed, _ = signed
    target = skill / extra
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("unsigned")
    with pytest.raises(ManifestError, match="not listed in the manifest"):
        manifest_v2.verify_skill(skill, allowed)


def test_verify_refuses_a_listed_file_replaced_by_a_symlink(tmp_path, signed):
    skill, _, allowed, _ = signed
    target = tmp_path / "same-content.py"
    target.write_text("print('hi')\n")
    (skill / "scripts" / "run.py").unlink()
    os.symlink(target, skill / "scripts" / "run.py")
    with pytest.raises(ManifestError, match="symbolic links"):
        manifest_v2.verify_skill(skill, allowed)


def test_verify_refuses_a_symlinked_manifest(tmp_path, signed):
    skill, _, allowed, _ = signed
    real = tmp_path / "real-manifest.json"
    (skill / "MANIFEST.json").rename(real)
    os.symlink(real, skill / "MANIFEST.json")
    with pytest.raises(ManifestError, match="MANIFEST.json"):
        manifest_v2.verify_skill(skill, allowed)


def test_verify_refuses_a_missing_signature(signed):
    skill, _, allowed, _ = signed
    (skill / "MANIFEST.json.sig").unlink()
    with pytest.raises(ManifestError, match="MANIFEST.json.sig"):
        manifest_v2.verify_skill(skill, allowed)


@pytest.mark.parametrize("change, message", [
    (lambda d: d.update(manifest_version=1), "unsupported manifest_version"),
    (lambda d: d.update(manifest_version=True), "unsupported manifest_version"),
    (lambda d: d.update(author="mallory"), "unknown field in manifest: 'author'"),
    (lambda d: d.update(name="Bad Name"), "invalid skill name"),
    (lambda d: d.pop("description"), "missing 'description'"),
    (lambda d: d.update(scripts=["nope.py"]), "is not in 'files'"),
    (lambda d: d["requires"].update(network="everything"), "requires.network"),
    (lambda d: d["requires"].update(hosts=["x"]), "unknown field in 'requires'"),
    (lambda d: d["files"].update({"../escape": d["files"]["SKILL.md"]}), "'..' component"),
    (lambda d: d["files"].update({"/abs": d["files"]["SKILL.md"]}), "must be relative"),
    (lambda d: d["files"].update({"skill.md": d["files"]["SKILL.md"]}), "letter case"),
    (lambda d: d["files"].update({"MANIFEST.json": d["files"]["SKILL.md"]}), "must not list itself"),
    (lambda d: d["files"]["SKILL.md"].update(size=-1), "invalid size"),
    (lambda d: d["files"]["SKILL.md"].update(sha256="ABC"), "invalid sha256"),
    (lambda d: d["files"]["SKILL.md"].update(mode="0755"), "exactly 'sha256' and 'size'"),
])
def test_verify_refuses_a_validly_signed_but_malformed_manifest(signed, change, message):
    skill, key, allowed, _ = signed
    rewrite_manifest(skill, change)
    resign_raw(skill, key)
    with pytest.raises(ManifestError, match=message):
        manifest_v2.verify_skill(skill, allowed)


def test_verify_refuses_duplicate_keys(signed):
    skill, key, allowed, _ = signed
    path = skill / "MANIFEST.json"
    path.write_text(path.read_text().replace('{\n', '{\n  "name": "other",\n', 1))
    resign_raw(skill, key)
    with pytest.raises(ManifestError, match="duplicate key in manifest: 'name'"):
        manifest_v2.verify_skill(skill, allowed)


# ------------------------------------------------------------------- CLI

def test_cli_sign_verify_inspect(tmp_path, skill):
    key = make_key(tmp_path)
    allowed = trust(tmp_path, (IDENTITY, key))

    out, code = run_cli(
        "sign", str(skill), "--key", key, "--version", "2.0.0",
        "--script", "scripts/run.py", "--network", "loopback", "--secret", "API_TOKEN",
    )
    assert code == 0, out
    assert "Manifest SHA256:" in out
    assert not (skill / "MANIFEST.sig.json").exists()
    doc = json.loads((skill / "MANIFEST.json").read_text())
    assert doc["requires"] == {"network": "loopback", "secrets": ["API_TOKEN"], "read_only": []}

    out, code = run_cli("verify", str(skill), "--allowed-signers", allowed)
    assert code == 0, out
    assert f"Signer: {IDENTITY}" in out
    assert "All 3 files verified" in out

    out, code = run_cli("inspect", str(skill), "--verbose")
    assert code == 0, out
    assert "Manifest version: 2" in out
    assert "demo-skill v2.0.0" in out
    assert "Scripts: scripts/run.py" in out
    assert "Requires network: loopback" in out

    (skill / "added.txt").write_text("x")
    out, code = run_cli("verify", str(skill), "--allowed-signers", allowed)
    assert code == 1
    assert "not listed in the manifest: added.txt" in out


def test_cli_sign_needs_no_identity(tmp_path, skill):
    out, code = run_cli("sign", str(skill), "--key", make_key(tmp_path))
    assert code == 0, out


def test_cli_sign_refuses_gpg_for_version_2(tmp_path, skill):
    out, code = run_cli("sign", str(skill), "--key", make_key(tmp_path), "--key-type", "gpg")
    assert code == 1
    assert "SSH keys only" in out


def test_cli_sign_reports_clutter(tmp_path, skill):
    (skill / ".DS_Store").write_bytes(b"\0")
    out, code = run_cli("sign", str(skill), "--key", make_key(tmp_path))
    assert code == 0, out
    assert "not meant to be published" in out
    assert ".DS_Store" in json.loads((skill / "MANIFEST.json").read_text())["files"]


def sign_v1(tmp_path, skill):
    key = make_key(tmp_path)
    out, code = run_cli(
        "sign", str(skill), "--manifest-version", "1", "--key", key,
        "--identity", IDENTITY, "--version", "3.1.4",
    )
    assert code == 0, out
    return key, trust(tmp_path, (IDENTITY, key))


def test_cli_version_1_still_signs_and_verifies(tmp_path, skill):
    _, allowed = sign_v1(tmp_path, skill)
    assert (skill / "MANIFEST.sig.json").exists()
    assert not (skill / "MANIFEST.json").exists()
    out, code = run_cli("verify", str(skill), "--allowed-signers", allowed)
    assert code == 0, out
    assert "version 1 manifest" in out


def test_cli_sign_refuses_to_mix_versions(tmp_path, skill):
    key, _ = sign_v1(tmp_path, skill)
    out, code = run_cli("sign", str(skill), "--key", key)
    assert code == 1
    assert "resign" in out
    assert not (skill / "MANIFEST.json").exists()


def test_cli_resign_replaces_version_1(tmp_path, skill):
    key, allowed = sign_v1(tmp_path, skill)
    out, code = run_cli("resign", str(skill), "--key", key, "--allowed-signers", allowed)
    assert code == 0, out
    assert not (skill / "MANIFEST.sig.json").exists()
    doc = json.loads((skill / "MANIFEST.json").read_text())
    assert doc["version"] == "3.1.4"
    # Version 1 left the dotfile out; version 2 lists it.
    assert ".hidden" in doc["files"]
    assert "MANIFEST.sig.json" not in doc["files"]
    out, code = run_cli("verify", str(skill), "--allowed-signers", allowed)
    assert code == 0, out


def test_cli_resign_refuses_a_tampered_version_1_skill(tmp_path, skill):
    key, allowed = sign_v1(tmp_path, skill)
    (skill / "scripts" / "run.py").write_text("print('changed')\n")
    out, code = run_cli("resign", str(skill), "--key", key, "--allowed-signers", allowed)
    assert code == 1
    assert "was not re-signed" in out
    assert (skill / "MANIFEST.sig.json").exists()
    assert not (skill / "MANIFEST.json").exists()

    out, code = run_cli(
        "resign", str(skill), "--key", key, "--allowed-signers", allowed, "--skip-check"
    )
    assert code == 0, out
    assert not (skill / "MANIFEST.sig.json").exists()


def test_cli_resign_keeps_version_1_when_version_2_cannot_be_built(tmp_path):
    d = tmp_path / "bare"
    d.mkdir()
    (d / "SKILL.md").write_text("# Bare\n")
    key, allowed = sign_v1(tmp_path, d)
    out, code = run_cli("resign", str(d), "--key", key, "--allowed-signers", allowed)
    assert code == 1
    assert "needs a description" in out
    assert (d / "MANIFEST.sig.json").exists()
    assert not (d / "MANIFEST.json").exists()


def test_cli_publish_explains_version_2(tmp_path, skill):
    run_cli("sign", str(skill), "--key", make_key(tmp_path))
    out, code = run_cli("publish", str(skill), "--registry", "http://127.0.0.1:1")
    assert code == 1
    assert "registry does not accept yet" in out
