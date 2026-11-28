#!/usr/bin/env python3
"""
Tests for publish functionality.

Note: These tests use a real temporary skill directory and mock the manifest
loading, signature verification and registry requests.
"""

import tarfile

import pytest
from unittest.mock import Mock, patch


def make_args(skill_dir, **overrides):
    """Build the argparse-style namespace cmd_publish() expects."""
    args = Mock()
    args.skill_dir = str(skill_dir)
    args.registry = None
    args.register_identity = False
    args.dry_run = False
    args.allowed_signers = None
    args.key = None
    for name, value in overrides.items():
        setattr(args, name, value)
    return args


class TestPublishCommand:
    """Tests for cmd_publish()."""

    @pytest.fixture
    def skill_dir(self, tmp_path):
        """Create a real skill directory with a manifest and one signed file.

        The manifest content is a placeholder: load_manifest is mocked.
        """
        skill = tmp_path / "skill"
        skill.mkdir()
        (skill / "README.md").write_text("# Test skill\n")
        (skill / "MANIFEST.sig.json").write_text("{}")
        return skill

    @pytest.fixture
    def allowed_signers(self, tmp_path):
        """Create a real allowed_signers file (verify_manifest is mocked)."""
        path = tmp_path / "allowed_signers"
        path.write_text("")
        return str(path)

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
    def mock_config(self, allowed_signers):
        """Create a mock config object."""
        config = Mock()
        config.registry_url = "http://localhost:8400"
        config.registry_auto_register = True
        config.verification_allowed_signers = allowed_signers
        config.signing_key = "/tmp/test_key"
        return config

    @patch('lib.cli.load_config')
    @patch('lib.cli.load_manifest')
    def test_publish_no_manifest(self, mock_load_manifest, mock_load_config, tmp_path, capsys):
        """Test publish when manifest doesn't exist."""
        from lib.cli import cmd_publish

        empty_dir = tmp_path / "skill"
        empty_dir.mkdir()

        result = cmd_publish(make_args(empty_dir))
        assert result == 1

        captured = capsys.readouterr()
        assert "No manifest found" in captured.err
        mock_load_manifest.assert_not_called()

    @patch('lib.cli.load_config')
    @patch('lib.cli.load_manifest')
    def test_publish_no_registry_url(
        self, mock_load_manifest, mock_load_config, skill_dir, allowed_signers, capsys
    ):
        """Test publish when no registry URL is provided."""
        from lib.cli import cmd_publish

        config = Mock()
        config.registry_url = None
        config.verification_allowed_signers = allowed_signers
        mock_load_config.return_value = config

        with patch.dict('os.environ', {}, clear=True):
            result = cmd_publish(make_args(skill_dir))

        assert result == 1
        captured = capsys.readouterr()
        assert "No registry URL" in captured.err

    @patch('lib.cli.load_config')
    @patch('lib.cli.load_manifest')
    @patch('lib.manifest.verify_manifest')
    @patch('lib.manifest.hash_file')
    @patch('requests.get')
    @patch('requests.post')
    def test_publish_dry_run(
        self,
        mock_post,
        mock_get,
        mock_hash_file,
        mock_verify,
        mock_load_manifest,
        mock_load_config,
        mock_manifest,
        mock_config,
        skill_dir,
        capsys
    ):
        """Test publish in dry-run mode."""
        from lib.cli import cmd_publish

        mock_load_config.return_value = mock_config
        mock_load_manifest.return_value = mock_manifest
        mock_verify.return_value = Mock(valid=True)
        mock_hash_file.return_value = Mock(sha256="abc123")

        result = cmd_publish(make_args(skill_dir, dry_run=True))
        assert result == 0

        captured = capsys.readouterr()
        assert "PUBLISH PREVIEW" in captured.out
        mock_load_manifest.assert_called_once_with(str(skill_dir / "MANIFEST.sig.json"))
        mock_verify.assert_called_once()
        # Dry-run must not contact the registry at all
        assert mock_get.call_count == 0
        assert mock_post.call_count == 0

    @patch('lib.cli.load_config')
    @patch('lib.cli.load_manifest')
    @patch('lib.manifest.verify_manifest')
    @patch('lib.manifest.hash_file')
    @patch('requests.get')
    @patch('requests.post')
    def test_publish_success(
        self,
        mock_post,
        mock_get,
        mock_hash_file,
        mock_verify,
        mock_load_manifest,
        mock_load_config,
        mock_manifest,
        mock_config,
        skill_dir,
        capsys
    ):
        """Test successful publish."""
        from lib.cli import cmd_publish

        mock_load_config.return_value = mock_config
        mock_load_manifest.return_value = mock_manifest
        mock_verify.return_value = Mock(valid=True)
        mock_hash_file.return_value = Mock(sha256="abc123")

        # Mock registry responses
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: [{"email": "test@example.com", "approved": True}]
        )

        # Inspect the uploaded package while the file handle is still open
        uploaded = {}

        def fake_post(url, files=None, data=None, **kwargs):
            filename, fileobj, content_type = files['package']
            uploaded['url'] = url
            uploaded['filename'] = filename
            uploaded['tarball_path'] = fileobj.name
            uploaded['manifest'] = data['manifest']
            with tarfile.open(fileobj=fileobj, mode='r:gz') as tar:
                uploaded['members'] = tar.getnames()
            return Mock(
                status_code=201,
                json=lambda: {"url": "http://registry/skills/test-skill"}
            )

        mock_post.side_effect = fake_post

        result = cmd_publish(make_args(skill_dir))
        assert result == 0

        captured = capsys.readouterr()
        assert "published successfully" in captured.out.lower()

        assert uploaded['url'] == "http://localhost:8400/skills/submit"
        assert uploaded['filename'] == "test-skill-1.0.0.tar.gz"
        assert uploaded['manifest'] == '{"test": "data"}'
        assert uploaded['members'] == ["README.md"]
        # The temporary tarball is removed after the upload
        from pathlib import Path
        assert not Path(uploaded['tarball_path']).exists()

    @patch('lib.cli.load_config')
    @patch('lib.cli.load_manifest')
    @patch('lib.manifest.verify_manifest')
    @patch('lib.manifest.hash_file')
    @patch('requests.get')
    @patch('requests.post')
    def test_publish_identity_not_registered(
        self,
        mock_post,
        mock_get,
        mock_hash_file,
        mock_verify,
        mock_load_manifest,
        mock_load_config,
        mock_manifest,
        skill_dir,
        allowed_signers,
        capsys
    ):
        """Test publish when identity is not registered."""
        from lib.cli import cmd_publish

        config = Mock()
        config.registry_url = "http://localhost:8400"
        config.registry_auto_register = False  # Don't auto-register
        config.verification_allowed_signers = allowed_signers
        mock_load_config.return_value = config

        mock_load_manifest.return_value = mock_manifest
        mock_verify.return_value = Mock(valid=True)
        mock_hash_file.return_value = Mock(sha256="abc123")

        # Mock registry response - identity not found
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: []  # No identities
        )

        result = cmd_publish(make_args(skill_dir))
        assert result == 1

        captured = capsys.readouterr()
        assert "not registered" in captured.err.lower()
        assert mock_post.call_count == 0  # Nothing registered or submitted
