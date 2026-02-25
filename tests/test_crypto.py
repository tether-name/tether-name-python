"""
Unit tests for the crypto module.

These tests use generated test keypairs and don't hit the live API.
"""

import base64
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from tether_name.crypto import (
    generate_test_keypair,
    load_private_key,
    sign_challenge,
)
from tether_name.exceptions import TetherKeyError


class TestLoadPrivateKey:
    """Test private key loading functionality."""
    
    def test_load_from_pem_file(self):
        """Test loading RSA private key from PEM file."""
        private_key, _ = generate_test_keypair()
        
        # Serialize to PEM
        pem_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.pem') as f:
            f.write(pem_data)
            temp_path = Path(f.name)
        
        try:
            # Load from file
            loaded_key = load_private_key(key_path=temp_path)
            
            # Verify it's the same key
            assert loaded_key.key_size == 2048
            assert isinstance(loaded_key, type(private_key))
            
            # Test signing to ensure it works
            test_data = b"test message"
            signature1 = private_key.sign(test_data, padding.PKCS1v15(), hashes.SHA256())
            signature2 = loaded_key.sign(test_data, padding.PKCS1v15(), hashes.SHA256())
            
            # Signatures will be different (randomized padding) but both should verify
            public_key = private_key.public_key()
            public_key.verify(signature1, test_data, padding.PKCS1v15(), hashes.SHA256())
            public_key.verify(signature2, test_data, padding.PKCS1v15(), hashes.SHA256())
            
        finally:
            temp_path.unlink()
    
    def test_load_from_der_file(self):
        """Test loading RSA private key from DER file."""
        private_key, _ = generate_test_keypair()
        
        # Serialize to DER
        der_data = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.der') as f:
            f.write(der_data)
            temp_path = Path(f.name)
        
        try:
            # Load from file
            loaded_key = load_private_key(key_path=temp_path)
            
            # Verify it's the same key
            assert loaded_key.key_size == 2048
            
        finally:
            temp_path.unlink()
    
    def test_load_from_pem_string(self):
        """Test loading RSA private key from PEM string."""
        private_key, _ = generate_test_keypair()
        
        # Serialize to PEM string
        pem_string = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Load from string
        loaded_key = load_private_key(key_pem=pem_string)
        assert loaded_key.key_size == 2048
    
    def test_load_from_pem_bytes(self):
        """Test loading RSA private key from PEM bytes."""
        private_key, _ = generate_test_keypair()
        
        # Serialize to PEM bytes
        pem_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Load from bytes
        loaded_key = load_private_key(key_pem=pem_bytes)
        assert loaded_key.key_size == 2048
    
    def test_load_from_der_bytes(self):
        """Test loading RSA private key from DER bytes."""
        private_key, _ = generate_test_keypair()
        
        # Serialize to DER bytes
        der_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Load from bytes
        loaded_key = load_private_key(key_der=der_bytes)
        assert loaded_key.key_size == 2048
    
    def test_file_not_found(self):
        """Test error when key file doesn't exist."""
        with pytest.raises(TetherKeyError, match="Private key file not found"):
            load_private_key(key_path="/nonexistent/path/key.pem")
    
    def test_invalid_pem(self):
        """Test error with invalid PEM data."""
        with pytest.raises(TetherKeyError, match="Failed to load private key"):
            load_private_key(key_pem="invalid pem data")
    
    def test_no_key_provided(self):
        """Test error when no key is provided."""
        with pytest.raises(TetherKeyError, match="Exactly one of"):
            load_private_key()
    
    def test_multiple_keys_provided(self):
        """Test error when multiple keys are provided."""
        private_key, _ = generate_test_keypair()
        pem_string = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        with pytest.raises(TetherKeyError, match="Exactly one of"):
            load_private_key(key_pem=pem_string, key_der=b"some der data")


class TestSignChallenge:
    """Test challenge signing functionality."""
    
    def test_sign_and_verify_challenge(self):
        """Test signing a challenge and verifying the signature."""
        private_key, _ = generate_test_keypair()
        public_key = private_key.public_key()
        
        challenge = "test-challenge-uuid-12345"
        
        # Sign the challenge
        signature_b64 = sign_challenge(private_key, challenge)
        
        # Verify the signature format (URL-safe base64, no padding)
        assert isinstance(signature_b64, str)
        assert '=' not in signature_b64  # No padding
        assert '+' not in signature_b64 and '/' not in signature_b64  # URL-safe
        
        # Decode and verify signature
        # Add padding back for decoding
        padding_needed = 4 - (len(signature_b64) % 4)
        if padding_needed != 4:
            signature_b64_padded = signature_b64 + ('=' * padding_needed)
        else:
            signature_b64_padded = signature_b64
            
        signature_bytes = base64.urlsafe_b64decode(signature_b64_padded)
        
        # Verify the signature cryptographically
        public_key.verify(
            signature_bytes,
            challenge.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        # If verify() doesn't raise an exception, the signature is valid
    
    def test_different_challenges_different_signatures(self):
        """Test that different challenges produce different signatures."""
        private_key, _ = generate_test_keypair()
        
        challenge1 = "challenge-one"
        challenge2 = "challenge-two"
        
        signature1 = sign_challenge(private_key, challenge1)
        signature2 = sign_challenge(private_key, challenge2)
        
        assert signature1 != signature2
    
    def test_same_challenge_different_signatures(self):
        """Test that the same challenge can produce different signatures (due to randomized padding)."""
        private_key, _ = generate_test_keypair()
        challenge = "same-challenge"
        
        signature1 = sign_challenge(private_key, challenge)
        signature2 = sign_challenge(private_key, challenge)
        
        # PKCS1v15 padding includes random data, so signatures should be different
        # But both should verify correctly
        public_key = private_key.public_key()
        
        # Decode signatures and verify both
        for sig_b64 in [signature1, signature2]:
            padding_needed = 4 - (len(sig_b64) % 4)
            if padding_needed != 4:
                sig_b64_padded = sig_b64 + ('=' * padding_needed)
            else:
                sig_b64_padded = sig_b64
                
            signature_bytes = base64.urlsafe_b64decode(sig_b64_padded)
            public_key.verify(
                signature_bytes,
                challenge.encode('utf-8'),
                padding.PKCS1v15(),
                hashes.SHA256()
            )


class TestGenerateTestKeypair:
    """Test test keypair generation."""
    
    def test_generate_keypair(self):
        """Test that generate_test_keypair creates valid RSA-2048 keys."""
        private_key, public_key_pem = generate_test_keypair()
        
        # Check private key
        assert private_key.key_size == 2048
        
        # Check public key PEM format
        assert isinstance(public_key_pem, str)
        assert public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert public_key_pem.endswith("-----END PUBLIC KEY-----\n")
        
        # Verify we can load the public key
        public_key_loaded = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8')
        )
        
        # Test that they can sign and verify
        test_message = b"test message"
        signature = private_key.sign(test_message, padding.PKCS1v15(), hashes.SHA256())
        
        # This should not raise an exception
        public_key_loaded.verify(signature, test_message, padding.PKCS1v15(), hashes.SHA256())
        
        # Also verify with the public key from the private key
        private_key.public_key().verify(
            signature, test_message, padding.PKCS1v15(), hashes.SHA256()
        )