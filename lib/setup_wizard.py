#!/usr/bin/env python3
"""
First-run setup wizard for skill-signer.

Guides users through key setup and configuration.
"""

import os
import sys
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from . import ssh_signer, gpg_signer
from .config import (
    DEFAULT_CONFIG_PATH,
    DEFAULT_CONFIG_DIR,
    save_config,
    load_config,
)


def print_header(text: str):
    """Print a section header."""
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def print_step(step: int, total: int, text: str):
    """Print a step indicator."""
    print(f"\n[Step {step}/{total}] {text}")


def prompt_yes_no(question: str, default: bool = True) -> bool:
    """
    Ask a yes/no question.

    Args:
        question: Question to ask
        default: Default value if user just presses Enter

    Returns:
        True for yes, False for no
    """
    default_str = "Y/n" if default else "y/N"
    while True:
        response = input(f"{question} ({default_str}): ").strip().lower()
        if not response:
            return default
        if response in ['y', 'yes']:
            return True
        if response in ['n', 'no']:
            return False
        print("Please enter 'y' or 'n'")


def prompt_choice(question: str, choices: list) -> str:
    """
    Ask user to choose from a list of options.

    Args:
        question: Question to ask
        choices: List of choice strings

    Returns:
        Selected choice
    """
    print(f"\n{question}")
    for i, choice in enumerate(choices, 1):
        print(f"  {i}. {choice}")

    while True:
        response = input(f"Enter choice (1-{len(choices)}): ").strip()
        try:
            idx = int(response) - 1
            if 0 <= idx < len(choices):
                return choices[idx]
        except ValueError:
            pass
        print(f"Please enter a number between 1 and {len(choices)}")


def find_existing_ssh_keys() -> list:
    """
    Find existing SSH keys in ~/.ssh.

    Returns:
        List of tuples (key_path, key_type)
    """
    ssh_dir = Path.home() / ".ssh"
    if not ssh_dir.exists():
        return []

    keys = []
    # Look for common SSH key names
    key_patterns = [
        "id_ed25519",
        "id_rsa",
        "id_ecdsa",
        "id_dsa",
    ]

    for pattern in key_patterns:
        key_path = ssh_dir / pattern
        if key_path.exists():
            # Check if it's a private key (not .pub)
            pub_path = ssh_dir / f"{pattern}.pub"
            if pub_path.exists():
                keys.append((str(key_path), "SSH"))

    return keys


def find_existing_gpg_keys() -> list:
    """
    Find existing GPG secret keys.

    Returns:
        List of tuples (key_id, uid)
    """
    keys = gpg_signer.list_gpg_keys()
    return [(key['key_id'], key['uid']) for key in keys]


def generate_ssh_key(name: str, email: str) -> Tuple[bool, str, Optional[str]]:
    """
    Generate a new SSH key.

    Args:
        name: Name/comment for the key
        email: Email address

    Returns:
        Tuple of (success, message, key_path)
    """
    key_dir = Path.home() / ".ssh"
    key_dir.mkdir(exist_ok=True)

    # Generate key path based on email
    key_name = "skill-signing-key"
    key_path = key_dir / key_name

    # Check if key already exists
    if key_path.exists():
        # Try with a number suffix
        for i in range(1, 10):
            key_path = key_dir / f"{key_name}-{i}"
            if not key_path.exists():
                break
        else:
            return False, "Could not find available key name", None

    # Generate key
    success, message = ssh_signer.generate_keypair(
        str(key_path),
        comment=email
    )

    if success:
        # Write metadata sidecar
        import json
        import datetime
        meta_path = f"{key_path}.meta"
        meta = {
            "identity": email,
            "created": datetime.datetime.utcnow().isoformat() + "Z",
        }
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        return True, message, str(key_path)
    else:
        return False, message, None


def generate_gpg_key_wizard(name: str, email: str) -> Tuple[bool, str, Optional[str]]:
    """
    Generate a new GPG key.

    Args:
        name: Real name
        email: Email address

    Returns:
        Tuple of (success, message, key_id)
    """
    print("\nGenerating GPG key (this may take a moment)...")

    # Export directory for backup
    export_dir = Path.home() / ".config" / "skill-signer" / "gpg-keys"

    success, message = gpg_signer.generate_keypair(name, email, str(export_dir))

    if success:
        # Get the key ID
        key_id = gpg_signer.get_gpg_key_fingerprint(email)
        return True, message, key_id
    else:
        return False, message, None


def setup_wizard() -> int:
    """
    Run the interactive setup wizard.

    Returns:
        Exit code (0 for success, 1 for error)
    """
    print_header("Skill-Signer Setup Wizard")
    print("\nWelcome! This wizard will help you set up signing keys for skill-signer.")

    # Step 1: Check for existing keys
    print_step(1, 5, "Checking for existing keys...")

    ssh_keys = find_existing_ssh_keys()
    gpg_keys = find_existing_gpg_keys()

    if ssh_keys:
        print(f"\nFound {len(ssh_keys)} existing SSH key(s):")
        for key_path, key_type in ssh_keys:
            print(f"  - {key_path}")

    if gpg_keys:
        print(f"\nFound {len(gpg_keys)} existing GPG key(s):")
        for key_id, uid in gpg_keys:
            print(f"  - {key_id}: {uid}")

    # Step 2: Choose key type
    print_step(2, 5, "Choose signing key")

    if ssh_keys or gpg_keys:
        use_existing = prompt_yes_no("\nWould you like to use an existing key?", default=True)
    else:
        print("\nNo existing keys found. We'll generate a new one.")
        use_existing = False

    selected_key = None
    selected_key_type = None
    selected_identity = None

    if use_existing:
        # Let user choose between SSH and GPG
        if ssh_keys and gpg_keys:
            key_type_choice = prompt_choice(
                "Which type of key would you like to use?",
                ["SSH", "GPG"]
            )
        elif ssh_keys:
            key_type_choice = "SSH"
        else:
            key_type_choice = "GPG"

        if key_type_choice == "SSH":
            if len(ssh_keys) == 1:
                selected_key = ssh_keys[0][0]
                print(f"\nUsing key: {selected_key}")
            else:
                key_paths = [key[0] for key in ssh_keys]
                selected_key = prompt_choice("Select an SSH key:", key_paths)

            selected_key_type = "ssh"

            # Try to get identity from .pub file
            pub_path = f"{selected_key}.pub"
            if os.path.exists(pub_path):
                with open(pub_path, 'r') as f:
                    parts = f.read().strip().split()
                    if len(parts) >= 3:
                        selected_identity = " ".join(parts[2:])

        else:  # GPG
            if len(gpg_keys) == 1:
                selected_key = gpg_keys[0][0]
                selected_identity = gpg_keys[0][1]
                print(f"\nUsing key: {selected_key} ({selected_identity})")
            else:
                key_choices = [f"{key_id}: {uid}" for key_id, uid in gpg_keys]
                selected_choice = prompt_choice("Select a GPG key:", key_choices)
                # Extract key_id from choice
                selected_key = selected_choice.split(':')[0]
                selected_identity = ':'.join(selected_choice.split(':')[1:]).strip()

            selected_key_type = "gpg"

    else:
        # Generate new key
        print_step(3, 5, "Generate new key")

        # Ask for key type
        key_type_choice = prompt_choice(
            "Which type of key would you like to generate?",
            ["SSH (recommended)", "GPG"]
        )

        # Get user info
        print("\nPlease enter your information:")
        name = input("Name: ").strip()
        email = input("Email: ").strip()

        if not name or not email:
            print("Error: Name and email are required", file=sys.stderr)
            return 1

        if "SSH" in key_type_choice:
            success, message, key_path = generate_ssh_key(name, email)
            if success:
                print(f"\n✓ {message}")
                selected_key = key_path
                selected_key_type = "ssh"
                selected_identity = email
            else:
                print(f"Error: {message}", file=sys.stderr)
                return 1

        else:  # GPG
            success, message, key_id = generate_gpg_key_wizard(name, email)
            if success:
                print(f"\n✓ {message}")
                selected_key = key_id
                selected_key_type = "gpg"
                selected_identity = email
            else:
                print(f"Error: {message}", file=sys.stderr)
                return 1

    # Step 4: Prompt for identity if not auto-detected
    if not selected_identity:
        print_step(4, 5, "Set identity")
        print("\nWhat identity (email) should be used for signing?")
        selected_identity = input("Email: ").strip()

        if not selected_identity:
            print("Error: Identity is required", file=sys.stderr)
            return 1

    # Normalize identity to lowercase
    selected_identity = selected_identity.lower()

    # Step 5: Create config file
    print_step(5, 5, "Save configuration")

    config_exists = os.path.exists(DEFAULT_CONFIG_PATH)
    if config_exists:
        print(f"\nConfig file already exists: {DEFAULT_CONFIG_PATH}")
        update_config = prompt_yes_no("Update with new key settings?", default=True)
    else:
        update_config = prompt_yes_no(
            f"Create config file at {DEFAULT_CONFIG_PATH}?",
            default=True
        )

    if update_config:
        # Load existing config or create new
        if config_exists:
            existing_config = load_config()
            config_data = existing_config._data
        else:
            config_data = {
                "verification": {
                    "allowed_signers": os.path.join(DEFAULT_CONFIG_DIR, "allowed_signers"),
                    "tofu": False,
                },
                "registry": {
                    "url": "http://54.219.240.149:8400",
                    "auto_register": True,
                },
            }

        # Update signing section
        config_data["signing"] = {
            "key": selected_key,
            "identity": selected_identity,
        }

        if save_config(config_data):
            print(f"\n✓ Config saved to {DEFAULT_CONFIG_PATH}")
        else:
            print(f"\nWarning: Could not save config. You may need to install PyYAML:", file=sys.stderr)
            print("  pip install pyyaml", file=sys.stderr)

    # Optional: Register with registry
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)

    print(f"\nYour signing key is configured:")
    print(f"  Type:     {selected_key_type.upper()}")
    print(f"  Key:      {selected_key}")
    print(f"  Identity: {selected_identity}")

    print("\nYou can now sign skills with:")
    print("  skill-signer sign <skill-directory>")

    print("\nTo publish skills to a registry:")
    print("  skill-signer publish <skill-directory>")

    return 0


if __name__ == "__main__":
    sys.exit(setup_wizard())
