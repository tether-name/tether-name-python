"""
Cryptographic operations for Tether.name SDK.
"""

import base64
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .exceptions import TetherKeyError


def load_private_key(
    key_path: Union[str, Path, None] = None,
    key_pem: Union[str, bytes, None] = None,
    key_der: Union[bytes, None] = None,
) -> RSAPrivateKey:
    """
    Load an RSA private key from file path, PEM string/bytes, or DER bytes.
    
    Args:
        key_path: Path to the private key file (PEM or DER format)
        key_pem: PEM-formatted private key as string or bytes
        key_der: DER-formatted private key as bytes
        
    Returns:
        RSAPrivateKey: The loaded private key
        
    Raises:
        TetherKeyError: If the key cannot be loaded or is not an RSA key
    """
    if sum(x is not None for x in [key_path, key_pem, key_der]) != 1:
        raise TetherKeyError(
            "Exactly one of key_path, key_pem, or key_der must be provided"
        )
    
    try:
        if key_path is not None:
            key_path = Path(key_path)
            if not key_path.exists():
                raise TetherKeyError(f"Private key file not found: {key_path}")
            
            key_data = key_path.read_bytes()
            
            # Try PEM first, then DER
            try:
                private_key = serialization.load_pem_private_key(
                    key_data, password=None
                )
            except ValueError:
                try:
                    private_key = serialization.load_der_private_key(
                        key_data, password=None
                    )
                except ValueError:
                    raise TetherKeyError(
                        "Unable to load private key - not a valid PEM or DER file"
                    )
                    
        elif key_pem is not None:
            if isinstance(key_pem, str):
                key_pem = key_pem.encode('utf-8')
            
            private_key = serialization.load_pem_private_key(
                key_pem, password=None
            )
            
        elif key_der is not None:
            private_key = serialization.load_der_private_key(
                key_der, password=None
            )
            
        # Ensure it's an RSA key
        if not isinstance(private_key, RSAPrivateKey):
            raise TetherKeyError("Private key must be an RSA key")
            
        # Ensure it's 2048 bits (as required by Tether)
        key_size = private_key.key_size
        if key_size != 2048:
            raise TetherKeyError(
                f"Private key must be 2048 bits, got {key_size} bits"
            )
            
        return private_key
        
    except Exception as e:
        if isinstance(e, TetherKeyError):
            raise
        raise TetherKeyError(f"Failed to load private key: {e}")


def sign_challenge(private_key: RSAPrivateKey, challenge: str) -> str:
    """
    Sign a challenge string with the private key using SHA256withRSA.
    
    Args:
        private_key: The RSA private key to sign with
        challenge: The challenge string to sign
        
    Returns:
        str: Base64-encoded signature (URL-safe, no padding)
        
    Raises:
        TetherKeyError: If signing fails
    """
    try:
        # Sign the challenge using SHA256withRSA (PKCS1v15 padding)
        signature = private_key.sign(
            challenge.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        # Return as URL-safe base64 without padding
        return base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')
        
    except Exception as e:
        raise TetherKeyError(f"Failed to sign challenge: {e}")


def generate_test_keypair() -> tuple[RSAPrivateKey, str]:
    """
    Generate a test RSA-2048 keypair for testing purposes.
    
    Returns:
        tuple: (private_key, public_key_pem)
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_key, public_key_pem