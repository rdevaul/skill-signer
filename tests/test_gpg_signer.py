#!/usr/bin/env python3
"""
Tests for GPG signing functionality.

Note: These tests mock subprocess calls to avoid requiring GPG installation.
"""

import pytest
import subprocess
from unittest.mock import Mock, patch, mock_open, MagicMock
from lib import gpg_signer


class TestCheckGPGAvailable:
    """Tests for check_gpg_available()."""

    @patch('subprocess.run')
    def test_gpg_available(self, mock_run):
        """Test when GPG is available."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="gpg (GnuPG) 2.4.0\nCopyright...",
        )

        available, msg = gpg_signer.check_gpg_available()
        assert available is True
        assert "gpg (GnuPG)" in msg

    @patch('subprocess.run')
    def test_gpg_not_found(self, mock_run):
        """Test when GPG is not installed."""
        mock_run.side_effect = FileNotFoundError()

        available, msg = gpg_signer.check_gpg_available()
        assert available is False
        assert "not found" in msg.lower()


class TestListGPGKeys:
    """Tests for list_gpg_keys()."""

    @patch('subprocess.run')
    def test_list_keys_success(self, mock_run):
        """Test listing GPG secret keys."""
        mock_output = """sec:u:4096:1:ABCD1234EFGH5678:1234567890:::u:::scESC:::+:::23::0:
fpr:::::::::ABCD1234EFGH5678ABCD1234EFGH5678:
uid:u::::1234567890::Test User <test@example.com>::::::::::0:
"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout=mock_output
        )

        keys = gpg_signer.list_gpg_keys()
        assert len(keys) == 1
        assert keys[0]['key_id'] == 'EFGH5678'
        assert keys[0]['fingerprint'] == 'ABCD1234EFGH5678ABCD1234EFGH5678'
        assert 'uid' in keys[0]

    @patch('subprocess.run')
    def test_list_keys_empty(self, mock_run):
        """Test when no keys are available."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout=""
        )

        keys = gpg_signer.list_gpg_keys()
        assert keys == []


class TestGetGPGKeyFingerprint:
    """Tests for get_gpg_key_fingerprint()."""

    @patch('subprocess.run')
    def test_get_fingerprint_success(self, mock_run):
        """Test getting fingerprint."""
        mock_output = """pub:u:4096:1:ABCD1234EFGH5678:1234567890:::u:::scESC:::+:::23::0:
fpr:::::::::ABCD1234EFGH5678ABCD1234EFGH5678IJKL9012:
"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout=mock_output
        )

        fingerprint = gpg_signer.get_gpg_key_fingerprint("test@example.com")
        assert fingerprint == "ABCD1234EFGH5678ABCD1234EFGH5678IJKL9012"

    @patch('subprocess.run')
    def test_get_fingerprint_not_found(self, mock_run):
        """Test when key is not found."""
        mock_run.side_effect = subprocess.CalledProcessError(2, 'gpg')

        fingerprint = gpg_signer.get_gpg_key_fingerprint("invalid@example.com")
        assert fingerprint is None


class TestExportGPGPubkey:
    """Tests for export_gpg_pubkey()."""

    @patch('subprocess.run')
    def test_export_success(self, mock_run):
        """Test exporting public key."""
        mock_pubkey = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGXXXXXXBEAC...
-----END PGP PUBLIC KEY BLOCK-----"""

        mock_run.return_value = Mock(
            returncode=0,
            stdout=mock_pubkey
        )

        pubkey = gpg_signer.export_gpg_pubkey("test@example.com")
        assert pubkey == mock_pubkey.strip()

    @patch('subprocess.run')
    def test_export_failure(self, mock_run):
        """Test export failure."""
        mock_run.side_effect = subprocess.CalledProcessError(2, 'gpg')

        pubkey = gpg_signer.export_gpg_pubkey("test@example.com")
        assert pubkey is None


class TestSignData:
    """Tests for sign_data()."""

    @patch('subprocess.run')
    def test_sign_success(self, mock_run):
        """Test successful signing."""
        mock_signature = """-----BEGIN PGP SIGNATURE-----

iQIzBAABCAAdFiEE...
-----END PGP SIGNATURE-----"""

        mock_run.return_value = Mock(
            returncode=0,
            stdout=mock_signature.encode('utf-8')
        )

        result = gpg_signer.sign_data(b"test data", "ABCD1234")
        assert result.success is True
        assert result.signature == mock_signature

    @patch('subprocess.run')
    def test_sign_failure(self, mock_run):
        """Test signing failure."""
        mock_run.return_value = Mock(
            returncode=2,
            stderr=b"signing failed: secret key not available"
        )

        result = gpg_signer.sign_data(b"test data", "INVALID")
        assert result.success is False
        assert "failed" in result.error.lower()


class TestVerifyData:
    """Tests for verify_data()."""

    @patch('subprocess.run')
    @patch('os.path.exists', return_value=True)
    @patch('os.unlink')
    @patch('tempfile.NamedTemporaryFile')
    def test_verify_success(self, mock_tempfile, mock_unlink, mock_exists, mock_run):
        """Test successful verification."""
        mock_run.return_value = Mock(
            returncode=0,
            stderr='gpg: Good signature from "Test User <test@example.com>"'
        )

        # Mock temp files
        mock_data_file = MagicMock()
        mock_data_file.name = '/tmp/data123'
        mock_data_file.__enter__.return_value = mock_data_file

        mock_sig_file = MagicMock()
        mock_sig_file.name = '/tmp/sig123'
        mock_sig_file.__enter__.return_value = mock_sig_file

        mock_tempfile.side_effect = [mock_data_file, mock_sig_file]

        result = gpg_signer.verify_data(
            b"test data",
            "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----",
            "test@example.com"
        )

        assert result.valid is True

    @patch('subprocess.run')
    @patch('os.path.exists', return_value=True)
    @patch('os.unlink')
    @patch('tempfile.NamedTemporaryFile')
    def test_verify_failure(self, mock_tempfile, mock_unlink, mock_exists, mock_run):
        """Test verification failure."""
        mock_run.return_value = Mock(
            returncode=1,
            stderr='gpg: BAD signature from "Test User <test@example.com>"'
        )

        # Mock temp files
        mock_data_file = MagicMock()
        mock_data_file.name = '/tmp/data123'
        mock_data_file.__enter__.return_value = mock_data_file

        mock_sig_file = MagicMock()
        mock_sig_file.name = '/tmp/sig123'
        mock_sig_file.__enter__.return_value = mock_sig_file

        mock_tempfile.side_effect = [mock_data_file, mock_sig_file]

        result = gpg_signer.verify_data(
            b"test data",
            "-----BEGIN PGP SIGNATURE-----\n...\n-----END PGP SIGNATURE-----",
            "test@example.com"
        )

        assert result.valid is False


class TestGenerateKeypair:
    """Tests for generate_keypair()."""

    @patch('subprocess.run')
    @patch('lib.gpg_signer.get_gpg_key_fingerprint')
    @patch('lib.gpg_signer.export_gpg_pubkey')
    @patch('os.makedirs')
    @patch('builtins.open', new_callable=mock_open)
    def test_generate_success(self, mock_file, mock_makedirs, mock_export, mock_fingerprint, mock_run):
        """Test successful key generation."""
        mock_run.return_value = Mock(returncode=0, stderr="")
        mock_fingerprint.return_value = "ABCD1234EFGH5678"
        mock_export.return_value = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n...\n"

        success, message = gpg_signer.generate_keypair(
            "Test User",
            "test@example.com",
            "/tmp/output"
        )

        assert success is True
        assert "Generated" in message

    @patch('subprocess.run')
    def test_generate_failure(self, mock_run):
        """Test key generation failure."""
        mock_run.return_value = Mock(
            returncode=2,
            stderr="Key generation failed"
        )

        success, message = gpg_signer.generate_keypair(
            "Test User",
            "test@example.com"
        )

        assert success is False
        assert "failed" in message.lower()
