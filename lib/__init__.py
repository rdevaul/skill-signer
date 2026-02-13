"""skill-signer library."""

from .ssh_signer import (
    sign_data,
    verify_data,
    generate_keypair,
    get_key_fingerprint,
    check_ssh_version,
)

from .manifest import (
    SkillManifest,
    FileEntry,
    Dependency,
    SignerInfo,
    create_manifest,
    sign_manifest,
    save_manifest,
    load_manifest,
)

from .trust import (
    add_signer,
    revoke_signer,
    list_signers,
    fetch_pubkey,
)

__version__ = "0.1.0"
__all__ = [
    "sign_data",
    "verify_data", 
    "generate_keypair",
    "get_key_fingerprint",
    "check_ssh_version",
    "SkillManifest",
    "FileEntry",
    "Dependency",
    "SignerInfo",
    "create_manifest",
    "sign_manifest",
    "save_manifest",
    "load_manifest",
    "add_signer",
    "revoke_signer",
    "list_signers",
    "fetch_pubkey",
]
