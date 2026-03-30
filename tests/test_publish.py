#!/usr/bin/env python3
"""
Tests for publish functionality.

Note: These tests mock requests and file operations.
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path


class TestPublishCommand:
    """Tests for cmd_publish()."""

    @pytest.fixture
    def mock_manifest(self):
        """Create a mock manifest object."""
        manifest = Mock()
        manifest.skill_name = "test-skill"
        manifest.skill_version = "1.0.0"
        manifest.author = "test@example.com"
        manifest.signature = "mock-signature"
        manifest.signer = Mock()
        manifest.signer.identity = "test@example.com"
        manifest.signer.key_fingerprint = "SHA256:mock"
        manifest.signer.key_type = "ssh"
        manifest.files = {"README.md": Mock(sha256="abc123", size=100)}
        manifest.signing_payload = Mock(return_value=b"payload")
        manifest.to_json = Mock(return_value='{"test": "data"}')
        return manifest

    @pytest.fixture
    def mock_config(self):
        """Create a mock config object."""
        config = Mock()
        config.registry_url = "http://localhost:8400"
        config.registry_auto_register = True
        config.verification_allowed_signers = "/tmp/allowed_signers"
        config.signing_key = "/tmp/test_key"
        return config

    @patch('lib.cli.load_config')
    @patch('lib.cli.load_manifest')
    @patch('lib.cli.Path')
    @patch('os.path.exists')
    def test_publish_no_manifest(self, mock_exists, mock_path, mock_load_manifest, mock_load_config, capsys):
        """Test publish when manifest doesn't exist."""
        from lib.cli import cmd_publish

        mock_exists.return_value = False
        mock_path.return_value.resolve.return_value = Path("/tmp/skill")

        args = Mock()
        args.skill_dir = "/tmp/skill"
        args.registry = None
        args.register_identity = False
        args.dry_run = False
        args.allowed_signers = None
        args.key = None

        result = cmd_publish(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "No manifest found" in captured.err

    @patch('lib.cli.load_config')
    @patch('lib.cli.load_manifest')
    @patch('lib.cli.Path')
    @patch('os.path.exists')
    def test_publish_no_registry_url(self, mock_exists, mock_path, mock_load_manifest, mock_load_config, capsys):
        """Test publish when no registry URL is provided."""
        from lib.cli import cmd_publish

        mock_exists.return_value = True
        mock_path.return_value.resolve.return_value = Path("/tmp/skill")

        config = Mock()
        config.registry_url = None
        config.verification_allowed_signers = "/tmp/allowed_signers"
        mock_load_config.return_value = config

        args = Mock()
        args.skill_dir = "/tmp/skill"
        args.registry = None
        args.register_identity = False
        args.dry_run = False
        args.allowed_signers = None
        args.key = None

        with patch.dict('os.environ', {}, clear=True):
            result = cmd_publish(args)

        assert result == 1
        captured = capsys.readouterr()
        assert "No registry URL" in captured.err

    @patch('lib.cli.load_config')
    @patch('lib.cli.load_manifest')
    @patch('lib.manifest.verify_manifest')
    @patch('lib.manifest.hash_file')
    @patch('lib.cli.Path')
    @patch('os.path.exists')
    @patch('requests.get')
    @patch('requests.post')
    @patch('tarfile.open')
    @patch('tempfile.NamedTemporaryFile')
    @patch('builtins.open')
    def test_publish_dry_run(
        self,
        mock_open_file,
        mock_tempfile,
        mock_tarfile,
        mock_post,
        mock_get,
        mock_exists,
        mock_path,
        mock_hash_file,
        mock_verify,
        mock_load_manifest,
        mock_load_config,
        mock_manifest,
        mock_config,
        capsys
    ):
        """Test publish in dry-run mode."""
        from lib.cli import cmd_publish

        mock_exists.return_value = True
        mock_path.return_value.resolve.return_value = Path("/tmp/skill")
        mock_load_config.return_value = mock_config
        mock_load_manifest.return_value = mock_manifest

        verify_result = Mock()
        verify_result.valid = True
        mock_verify.return_value = verify_result

        hash_result = Mock()
        hash_result.sha256 = "abc123"
        mock_hash_file.return_value = hash_result

        args = Mock()
        args.skill_dir = "/tmp/skill"
        args.registry = None
        args.register_identity = False
        args.dry_run = True
        args.allowed_signers = None
        args.key = None

        result = cmd_publish(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "PUBLISH PREVIEW" in captured.out
        assert mock_post.call_count == 0  # Should not POST in dry-run

    @patch('lib.cli.load_config')
    @patch('lib.cli.load_manifest')
    @patch('lib.manifest.verify_manifest')
    @patch('lib.manifest.hash_file')
    @patch('lib.cli.Path')
    @patch('os.path.exists')
    @patch('os.unlink')
    @patch('requests.get')
    @patch('requests.post')
    @patch('tarfile.open')
    @patch('tempfile.NamedTemporaryFile')
    @patch('builtins.open')
    def test_publish_success(
        self,
        mock_open_file,
        mock_tempfile,
        mock_tarfile,
        mock_post,
        mock_get,
        mock_unlink,
        mock_exists,
        mock_path,
        mock_hash_file,
        mock_verify,
        mock_load_manifest,
        mock_load_config,
        mock_manifest,
        mock_config,
        capsys
    ):
        """Test successful publish."""
        from lib.cli import cmd_publish

        mock_exists.return_value = True
        mock_path.return_value.resolve.return_value = Path("/tmp/skill")
        mock_load_config.return_value = mock_config
        mock_load_manifest.return_value = mock_manifest

        verify_result = Mock()
        verify_result.valid = True
        mock_verify.return_value = verify_result

        hash_result = Mock()
        hash_result.sha256 = "abc123"
        mock_hash_file.return_value = hash_result

        # Mock registry responses
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: [{"email": "test@example.com", "approved": True}]
        )

        mock_post.return_value = Mock(
            status_code=201,
            json=lambda: {"url": "http://registry/skills/test-skill"}
        )

        # Mock tempfile
        mock_temp = Mock()
        mock_temp.name = "/tmp/package.tar.gz"
        mock_tempfile.return_value.__enter__.return_value = mock_temp

        # Mock tarfile
        mock_tar = MagicMock()
        mock_tarfile.return_value.__enter__.return_value = mock_tar

        args = Mock()
        args.skill_dir = "/tmp/skill"
        args.registry = None
        args.register_identity = False
        args.dry_run = False
        args.allowed_signers = None
        args.key = None

        result = cmd_publish(args)
        assert result == 0

        captured = capsys.readouterr()
        assert "published successfully" in captured.out.lower()

    @patch('lib.cli.load_config')
    @patch('lib.cli.load_manifest')
    @patch('lib.manifest.verify_manifest')
    @patch('lib.manifest.hash_file')
    @patch('lib.cli.Path')
    @patch('os.path.exists')
    @patch('requests.get')
    def test_publish_identity_not_registered(
        self,
        mock_get,
        mock_exists,
        mock_path,
        mock_hash_file,
        mock_verify,
        mock_load_manifest,
        mock_load_config,
        mock_manifest,
        mock_config,
        capsys
    ):
        """Test publish when identity is not registered."""
        from lib.cli import cmd_publish

        mock_exists.return_value = True
        mock_path.return_value.resolve.return_value = Path("/tmp/skill")

        config = Mock()
        config.registry_url = "http://localhost:8400"
        config.registry_auto_register = False  # Don't auto-register
        config.verification_allowed_signers = "/tmp/allowed_signers"
        mock_load_config.return_value = config

        mock_load_manifest.return_value = mock_manifest

        verify_result = Mock()
        verify_result.valid = True
        mock_verify.return_value = verify_result

        hash_result = Mock()
        hash_result.sha256 = "abc123"
        mock_hash_file.return_value = hash_result

        # Mock registry response - identity not found
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: []  # No identities
        )

        args = Mock()
        args.skill_dir = "/tmp/skill"
        args.registry = None
        args.register_identity = False
        args.dry_run = False
        args.allowed_signers = None
        args.key = None

        result = cmd_publish(args)
        assert result == 1

        captured = capsys.readouterr()
        assert "not registered" in captured.err.lower()
