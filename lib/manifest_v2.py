#!/usr/bin/env python3
"""
Skill manifest version 2.

A signed skill directory holds two files at its top:

    MANIFEST.json       the manifest
    MANIFEST.json.sig   an OpenSSH signature over the exact bytes of
                        MANIFEST.json, namespace "skill-manifest"

The signature covers the file as stored, so a verifier never re-encodes
JSON, and stock OpenSSH can check a skill with no other tool:

    ssh-keygen -Y verify -f allowed_signers -I alice@example.com \\
        -n skill-manifest -s MANIFEST.json.sig < MANIFEST.json

The manifest lists every file in the directory (no exclusions), the signer's
identity is not in it (it comes from the verifier's allowed_signers file, by
the key that signed), and a directory holding a symbolic link or any other
non-regular file is refused.

The rules checked here are the ones the xshell loader applies, so a skill
this module accepts is one xshell will load.
"""

import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .ssh_signer import NAMESPACE, sign_data

MANIFEST_NAME = "MANIFEST.json"
SIGNATURE_NAME = "MANIFEST.json.sig"
LEGACY_MANIFEST_NAME = "MANIFEST.sig.json"
MANIFEST_VERSION = 2

MAX_MANIFEST_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
MAX_FILES = 512
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MAX_PATH_BYTES = 255
MAX_DESCRIPTION_CHARS = 500

NAME_PATTERN = re.compile(r"[a-z][a-z0-9_-]{0,63}")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
NETWORK_LEVELS = ("none", "loopback", "full")

# Names that are almost never meant to be part of a published skill. They are
# still listed and signed (the format has no exclusions); `find_clutter`
# reports them so a publisher can remove them first.
CLUTTER_NAMES = {".git", ".DS_Store", "__pycache__", "node_modules", ".venv"}


class ManifestError(ValueError):
    """A skill directory or manifest breaks one of the version 2 rules."""


@dataclass
class Requires:
    """What a skill needs from a contained shell."""
    network: str = "none"
    secrets: List[str] = field(default_factory=list)
    read_only: List[str] = field(default_factory=list)

    def is_default(self) -> bool:
        return self.network == "none" and not self.secrets and not self.read_only


@dataclass
class ManifestV2:
    name: str
    version: str
    description: str
    files: Dict[str, Dict[str, Any]]
    scripts: List[str] = field(default_factory=list)
    requires: Requires = field(default_factory=Requires)

    def to_bytes(self) -> bytes:
        """The bytes written to MANIFEST.json, and the bytes that are signed."""
        doc = {
            "manifest_version": MANIFEST_VERSION,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "files": {
                path: {"sha256": self.files[path]["sha256"], "size": self.files[path]["size"]}
                for path in sorted(self.files)
            },
            "scripts": sorted(self.scripts),
            "requires": {
                "network": self.requires.network,
                "secrets": list(self.requires.secrets),
                "read_only": list(self.requires.read_only),
            },
        }
        return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


@dataclass
class VerifiedSkill:
    """A skill directory that passed every check."""
    manifest: ManifestV2
    signer: str
    manifest_sha256: str


# --------------------------------------------------------------------------
# Field rules
# --------------------------------------------------------------------------

def validate_name(name: Any) -> str:
    if not isinstance(name, str) or not NAME_PATTERN.fullmatch(name):
        raise ManifestError(
            f"invalid skill name {name!r}: use 1-64 characters of a-z, 0-9, '-' and '_', "
            "starting with a letter"
        )
    return name


def validate_description(description: Any) -> str:
    if not isinstance(description, str) or not description.strip():
        raise ManifestError("a skill needs a description")
    if len(description) > MAX_DESCRIPTION_CHARS:
        raise ManifestError(
            f"description is {len(description)} characters; the limit is {MAX_DESCRIPTION_CHARS}"
        )
    return description


def validate_path(path: Any) -> str:
    """Rule: relative, '/' separators, no '.' or '..', at most 255 bytes."""
    if not isinstance(path, str) or not path:
        raise ManifestError(f"invalid file path {path!r}")
    if len(path.encode("utf-8")) > MAX_PATH_BYTES:
        raise ManifestError(f"path is longer than {MAX_PATH_BYTES} bytes: {path!r}")
    if path.startswith("/") or "\\" in path or "\0" in path:
        raise ManifestError(f"path must be relative and use '/': {path!r}")
    for part in path.split("/"):
        if part in ("", ".", ".."):
            raise ManifestError(f"path has an empty, '.' or '..' component: {path!r}")
    return path


def _check_case_unique(paths) -> None:
    seen: Dict[str, str] = {}
    for path in paths:
        key = path.casefold()
        if key in seen:
            raise ManifestError(
                f"paths differ only by letter case: {seen[key]!r} and {path!r}"
            )
        seen[key] = path


def _validate_requires(value: Any) -> Requires:
    if value is None:
        return Requires()
    if not isinstance(value, dict):
        raise ManifestError("'requires' must be an object")
    unknown = set(value) - {"network", "secrets", "read_only"}
    if unknown:
        raise ManifestError(f"unknown field in 'requires': {sorted(unknown)[0]!r}")
    network = value.get("network", "none")
    if network not in NETWORK_LEVELS:
        raise ManifestError(f"'requires.network' must be one of {', '.join(NETWORK_LEVELS)}")
    lists = {}
    for key in ("secrets", "read_only"):
        items = value.get(key, [])
        if not isinstance(items, list) or not all(isinstance(i, str) and i for i in items):
            raise ManifestError(f"'requires.{key}' must be a list of non-empty strings")
        lists[key] = items
    return Requires(network=network, secrets=lists["secrets"], read_only=lists["read_only"])


# --------------------------------------------------------------------------
# Parsing
# --------------------------------------------------------------------------

def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate key in manifest: {key!r}")
        result[key] = value
    return result


def parse_manifest(data: bytes) -> ManifestV2:
    """Parse MANIFEST.json strictly: no unknown fields, no duplicate keys."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise ManifestError(f"{MANIFEST_NAME} is larger than 1 MiB")
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ManifestError(f"{MANIFEST_NAME} is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise ManifestError(f"{MANIFEST_NAME} must hold a JSON object")

    version = doc.get("manifest_version")
    if version != MANIFEST_VERSION or isinstance(version, bool):
        raise ManifestError(
            f"unsupported manifest_version {version!r}; this is a version {MANIFEST_VERSION} reader"
        )
    known = {"manifest_version", "name", "version", "description", "files", "scripts", "requires"}
    unknown = set(doc) - known
    if unknown:
        raise ManifestError(f"unknown field in manifest: {sorted(unknown)[0]!r}")
    for required in ("name", "version", "description", "files"):
        if required not in doc:
            raise ManifestError(f"manifest is missing {required!r}")

    name = validate_name(doc["name"])
    description = validate_description(doc["description"])
    if not isinstance(doc["version"], str) or not doc["version"]:
        raise ManifestError("'version' must be a non-empty string")

    files = doc["files"]
    if not isinstance(files, dict):
        raise ManifestError("'files' must be an object")
    if len(files) > MAX_FILES:
        raise ManifestError(f"a skill may hold at most {MAX_FILES} files")
    total = 0
    for path, entry in files.items():
        validate_path(path)
        if path in (MANIFEST_NAME, SIGNATURE_NAME):
            raise ManifestError(f"{path} must not list itself")
        if not isinstance(entry, dict) or set(entry) != {"sha256", "size"}:
            raise ManifestError(f"entry for {path!r} must hold exactly 'sha256' and 'size'")
        digest, size = entry["sha256"], entry["size"]
        if not isinstance(digest, str) or not SHA256_PATTERN.fullmatch(digest):
            raise ManifestError(f"entry for {path!r} has an invalid sha256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ManifestError(f"entry for {path!r} has an invalid size")
        total += size
    if total > MAX_TOTAL_BYTES:
        raise ManifestError("a skill may hold at most 64 MiB")
    _check_case_unique(files)

    scripts = doc.get("scripts", [])
    if not isinstance(scripts, list) or not all(isinstance(s, str) for s in scripts):
        raise ManifestError("'scripts' must be a list of paths")
    if len(set(scripts)) != len(scripts):
        raise ManifestError("'scripts' lists a path twice")
    for script in scripts:
        if script not in files:
            raise ManifestError(f"script {script!r} is not in 'files'")

    return ManifestV2(
        name=name,
        version=doc["version"],
        description=description,
        files=files,
        scripts=scripts,
        requires=_validate_requires(doc.get("requires")),
    )


# --------------------------------------------------------------------------
# Directory scan
# --------------------------------------------------------------------------

def _hash_regular_file(path: str) -> Tuple[str, int]:
    """Hash a file, refusing to follow a link put there after the scan."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ManifestError(f"not a regular file: {path}")
        sha256 = hashlib.sha256()
        size = 0
        while chunk := f.read(65536):
            sha256.update(chunk)
            size += len(chunk)
    return sha256.hexdigest(), size


def scan_directory(skill_dir: Path) -> Dict[str, Dict[str, Any]]:
    """
    Hash every file under skill_dir, at any depth, except the two manifest
    files at its top. Anything that is not a regular file or a directory
    (a symbolic link, device, socket or FIFO) is an error.
    """
    skill_dir = Path(skill_dir)
    top = os.lstat(skill_dir)
    if not stat.S_ISDIR(top.st_mode):
        raise ManifestError(f"not a directory: {skill_dir}")

    files: Dict[str, Dict[str, Any]] = {}
    total = 0
    pending = [""]
    while pending:
        rel_dir = pending.pop()
        with os.scandir(skill_dir / rel_dir if rel_dir else skill_dir) as entries:
            for entry in sorted(entries, key=lambda e: e.name):
                rel = f"{rel_dir}/{entry.name}" if rel_dir else entry.name
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    pending.append(rel)
                    continue
                if stat.S_ISLNK(mode):
                    raise ManifestError(f"symbolic links are not allowed in a skill: {rel}")
                if not stat.S_ISREG(mode):
                    raise ManifestError(f"not a regular file: {rel}")
                if rel in (MANIFEST_NAME, SIGNATURE_NAME):
                    continue
                validate_path(rel)
                if len(files) >= MAX_FILES:
                    raise ManifestError(f"a skill may hold at most {MAX_FILES} files")
                digest, size = _hash_regular_file(os.path.join(skill_dir, rel))
                total += size
                if total > MAX_TOTAL_BYTES:
                    raise ManifestError("a skill may hold at most 64 MiB")
                files[rel] = {"sha256": digest, "size": size}
    _check_case_unique(files)
    return files


def find_clutter(files) -> List[str]:
    """Listed paths that look like they were not meant to be published."""
    return sorted(p for p in files if CLUTTER_NAMES.intersection(p.split("/")))


def read_frontmatter(skill_dir: Path) -> Dict[str, str]:
    """
    Read simple `key: value` lines from SKILL.md's front matter (the block
    between two `---` lines at the top). Only plain one-line values are read.
    """
    try:
        lines = (Path(skill_dir) / "SKILL.md").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return {}
    if not lines or lines[0].strip() != "---":
        return {}
    result: Dict[str, str] = {}
    for line in lines[1:]:
        if line.strip() == "---":
            return result
        key, sep, value = line.partition(":")
        if sep and key.strip() and not key.startswith((" ", "\t", "#")):
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            if value:
                result[key.strip()] = value
    return {}  # no closing line: not front matter


# --------------------------------------------------------------------------
# Signing
# --------------------------------------------------------------------------

def build_manifest(
    skill_dir: Path,
    name: Optional[str] = None,
    version: Optional[str] = None,
    description: Optional[str] = None,
    scripts: Optional[List[str]] = None,
    requires: Optional[Requires] = None,
) -> ManifestV2:
    """
    Build a manifest for a directory.

    A value that is not given is taken from the directory's existing
    MANIFEST.json if there is one (so signing again keeps what was declared),
    then from SKILL.md's front matter, then, for the name, from the
    directory's name.
    """
    skill_dir = Path(skill_dir)
    previous: Optional[ManifestV2] = None
    manifest_path = skill_dir / MANIFEST_NAME
    if manifest_path.is_file() and not manifest_path.is_symlink():
        try:
            previous = parse_manifest(manifest_path.read_bytes())
        except ManifestError:
            previous = None
    front = read_frontmatter(skill_dir)

    if name is None:
        name = (previous.name if previous else None) or front.get("name") or skill_dir.resolve().name
    if version is None:
        version = (previous.version if previous else None) or front.get("version") or "0.0.0"
    if description is None:
        description = (previous.description if previous else None) or front.get("description")
        if description is None:
            raise ManifestError(
                "a skill needs a description: pass --description, or add a "
                "'description:' line to SKILL.md's front matter"
            )
    if scripts is None:
        scripts = list(previous.scripts) if previous else []
    if requires is None:
        requires = previous.requires if previous else Requires()

    files = scan_directory(skill_dir)
    scripts = [validate_path(s) for s in scripts]
    for script in scripts:
        if script not in files:
            raise ManifestError(f"script {script!r} is not a file in the skill")
    if not isinstance(version, str) or not version:
        raise ManifestError("'version' must be a non-empty string")

    manifest = ManifestV2(
        name=validate_name(name),
        version=version,
        description=validate_description(description),
        files=files,
        scripts=sorted(set(scripts)),
        requires=_validate_requires(
            {"network": requires.network, "secrets": requires.secrets, "read_only": requires.read_only}
        ),
    )
    if len(manifest.to_bytes()) > MAX_MANIFEST_BYTES:
        raise ManifestError(f"{MANIFEST_NAME} would be larger than 1 MiB")
    return manifest


def _replace(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".manifest-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise


def sign_skill(skill_dir: Path, manifest: ManifestV2, key_path: str) -> str:
    """
    Write MANIFEST.json and MANIFEST.json.sig. Returns the manifest's
    identity: the SHA-256 of MANIFEST.json's bytes.
    """
    skill_dir = Path(skill_dir)
    data = manifest.to_bytes()
    result = sign_data(data, key_path)
    if not result.success:
        raise ManifestError(f"signing failed: {result.error}")
    _replace(skill_dir / MANIFEST_NAME, data)
    _replace(skill_dir / SIGNATURE_NAME, result.signature.encode("ascii"))
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

def _read_top_file(skill_dir: Path, name: str, limit: int) -> bytes:
    path = os.path.join(skill_dir, name)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as e:
        raise ManifestError(f"cannot open {name}: {e.strerror}") from e
    with os.fdopen(fd, "rb") as f:
        if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
            raise ManifestError(f"{name} is not a regular file")
        data = f.read(limit + 1)
    if len(data) > limit:
        raise ManifestError(f"{name} is too large")
    return data


def _find_signers(signature_path: str, allowed_signers: str) -> List[str]:
    result = subprocess.run(
        ["ssh-keygen", "-Y", "find-principals", "-s", signature_path, "-f", allowed_signers],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def verify_signature(
    data: bytes, signature: bytes, allowed_signers: str, identity: Optional[str] = None
) -> str:
    """
    Check an OpenSSH signature over data and return the signer's identity.

    The signer is found in allowed_signers by the key that made the
    signature. If `identity` is given, the signature must be by that signer.
    """
    allowed_signers = os.path.expanduser(allowed_signers)
    if not os.path.isfile(allowed_signers):
        raise ManifestError(f"allowed_signers not found: {allowed_signers}")
    with tempfile.TemporaryDirectory() as tmp:
        signature_path = os.path.join(tmp, "sig")
        with open(signature_path, "wb") as f:
            f.write(signature)
        candidates = _find_signers(signature_path, allowed_signers)
        if not candidates:
            raise ManifestError("the signing key does not belong to any trusted signer")
        if identity is not None:
            if identity not in candidates:
                raise ManifestError(
                    f"signed by {', '.join(candidates)}, not by {identity}"
                )
            candidates = [identity]
        errors = []
        for candidate in candidates:
            result = subprocess.run(
                ["ssh-keygen", "-Y", "verify", "-f", allowed_signers, "-I", candidate,
                 "-n", NAMESPACE, "-s", signature_path],
                input=data, capture_output=True,
            )
            if result.returncode == 0:
                return candidate
            errors.append(result.stderr.decode("utf-8", "replace").strip())
    raise ManifestError(f"signature verification failed: {'; '.join(e for e in errors if e)}")


def check_files(skill_dir: Path, manifest: ManifestV2) -> None:
    """The files on disk must be exactly the listed ones, byte for byte."""
    actual = scan_directory(skill_dir)
    listed = manifest.files
    unlisted = sorted(set(actual) - set(listed))
    if unlisted:
        raise ManifestError(f"file is not listed in the manifest: {unlisted[0]}")
    missing = sorted(set(listed) - set(actual))
    if missing:
        raise ManifestError(f"listed file is missing: {missing[0]}")
    for path in sorted(listed):
        if actual[path]["size"] != listed[path]["size"] or actual[path]["sha256"] != listed[path]["sha256"]:
            raise ManifestError(f"file does not match the manifest: {path}")


def verify_skill(
    skill_dir: Path, allowed_signers: str, identity: Optional[str] = None
) -> VerifiedSkill:
    """
    Check a version 2 skill directory. Raises ManifestError on any failure.

    The signature is checked over the bytes of MANIFEST.json before those
    bytes are parsed.
    """
    skill_dir = Path(skill_dir)
    data = _read_top_file(skill_dir, MANIFEST_NAME, MAX_MANIFEST_BYTES)
    signature = _read_top_file(skill_dir, SIGNATURE_NAME, MAX_SIGNATURE_BYTES)
    signer = verify_signature(data, signature, allowed_signers, identity)
    manifest = parse_manifest(data)
    check_files(skill_dir, manifest)
    return VerifiedSkill(
        manifest=manifest, signer=signer, manifest_sha256=hashlib.sha256(data).hexdigest()
    )
