#!/usr/bin/env python3
"""
Configuration file support for skill-signer.

Reads from ~/.config/skill-signer/config.yaml if available.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any


DEFAULT_CONFIG_DIR = os.path.expanduser("~/.config/skill-signer")
DEFAULT_CONFIG_PATH = os.path.join(DEFAULT_CONFIG_DIR, "config.yaml")


class Config:
    """Configuration container with defaults."""

    def __init__(self, data: Optional[Dict[str, Any]] = None):
        """Initialize config with optional data dict."""
        self._data = data or {}

    @property
    def signing_key(self) -> Optional[str]:
        """Default signing key path."""
        key = self._data.get("signing", {}).get("key")
        if key:
            return os.path.expanduser(key)
        return None

    @property
    def signing_identity(self) -> Optional[str]:
        """Default signing identity."""
        return self._data.get("signing", {}).get("identity")

    @property
    def verification_allowed_signers(self) -> Optional[str]:
        """Default allowed_signers path for verification."""
        path = self._data.get("verification", {}).get("allowed_signers")
        if path:
            return os.path.expanduser(path)
        return None

    @property
    def verification_tofu(self) -> bool:
        """Whether TOFU (Trust On First Use) mode is enabled."""
        return self._data.get("verification", {}).get("tofu", False)

    @property
    def registry_url(self) -> Optional[str]:
        """Default registry URL."""
        return self._data.get("registry", {}).get("url")

    @property
    def registry_auto_register(self) -> bool:
        """Whether to automatically offer identity registration."""
        return self._data.get("registry", {}).get("auto_register", True)


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Load configuration from YAML file.

    Args:
        config_path: Optional path to config file. Defaults to ~/.config/skill-signer/config.yaml

    Returns:
        Config object with loaded settings (or defaults if file not found)
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    # If file doesn't exist, return empty config (all defaults)
    if not os.path.exists(config_path):
        return Config()

    # Try to load YAML if available
    try:
        import yaml

        with open(config_path, 'r') as f:
            data = yaml.safe_load(f)
            return Config(data or {})

    except ImportError:
        # PyYAML not installed - fall back to defaults
        return Config()

    except Exception as e:
        # Error reading/parsing config - fall back to defaults
        import sys
        print(f"Warning: Could not load config from {config_path}: {e}", file=sys.stderr)
        return Config()


def save_config(config_data: Dict[str, Any], config_path: Optional[str] = None) -> bool:
    """
    Save configuration to YAML file.

    Args:
        config_data: Configuration dictionary to save
        config_path: Optional path to config file. Defaults to ~/.config/skill-signer/config.yaml

    Returns:
        True if saved successfully, False otherwise
    """
    if config_path is None:
        config_path = DEFAULT_CONFIG_PATH

    # Ensure config directory exists
    os.makedirs(os.path.dirname(config_path), exist_ok=True)

    # Try to save with YAML if available
    try:
        import yaml

        with open(config_path, 'w') as f:
            yaml.safe_dump(config_data, f, default_flow_style=False, sort_keys=False)

        return True

    except ImportError:
        # PyYAML not installed
        import sys
        print(f"Warning: PyYAML not installed. Cannot save config.", file=sys.stderr)
        print(f"Install with: pip install pyyaml", file=sys.stderr)
        return False

    except Exception as e:
        import sys
        print(f"Error: Could not save config to {config_path}: {e}", file=sys.stderr)
        return False


def get_default_config_template() -> Dict[str, Any]:
    """
    Get a template configuration dictionary with examples.

    Returns:
        Dictionary with example configuration settings
    """
    return {
        "signing": {
            "key": "~/.ssh/skill-signing-key",
            "identity": "your-email@example.com",
        },
        "verification": {
            "allowed_signers": "~/.config/skill-signer/allowed_signers",
            "tofu": False,
        },
        "registry": {
            "url": "http://54.219.240.149:8400",
            "auto_register": True,
        },
    }


if __name__ == "__main__":
    # Test config loading
    config = load_config()
    print(f"Signing key: {config.signing_key}")
    print(f"Signing identity: {config.signing_identity}")
    print(f"Allowed signers: {config.verification_allowed_signers}")
    print(f"TOFU enabled: {config.verification_tofu}")
