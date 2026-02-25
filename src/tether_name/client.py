"""
Tether.name SDK client for agent identity verification.
"""

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

import httpx
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .crypto import load_private_key, sign_challenge
from .exceptions import TetherAPIError, TetherError, TetherVerificationError


@dataclass
class VerificationResult:
    """Result of a Tether.name verification attempt."""
    
    verified: bool
    agent_name: Optional[str] = None
    verify_url: Optional[str] = None
    email: Optional[str] = None
    registered_since: Optional[datetime] = None
    error: Optional[str] = None
    challenge: Optional[str] = None


class TetherClient:
    """
    Client for interacting with the Tether.name API.
    
    Example:
        >>> client = TetherClient(
        ...     credential_id="your-credential-id",
        ...     private_key_path="/path/to/key.der"
        ... )
        >>> result = client.verify()
        >>> if result.verified:
        ...     print(f"Verified as {result.agent_name}")
    """
    
    def __init__(
        self,
        credential_id: Optional[str] = None,
        private_key_path: Optional[Union[str, Path]] = None,
        private_key_pem: Optional[Union[str, bytes]] = None,
        private_key_der: Optional[bytes] = None,
        base_url: str = "https://api.tether.name",
        timeout: float = 30.0,
    ) -> None:
        """
        Initialize the Tether client.
        
        Args:
            credential_id: Your Tether credential ID (or set TETHER_CREDENTIAL_ID)
            private_key_path: Path to private key file (or set TETHER_PRIVATE_KEY_PATH)
            private_key_pem: Private key as PEM string/bytes
            private_key_der: Private key as DER bytes
            base_url: Base URL for the Tether API
            timeout: Request timeout in seconds
            
        Raises:
            TetherError: If required parameters are missing or invalid
        """
        # Get credential ID from parameter or environment
        self.credential_id = credential_id or os.getenv("TETHER_CREDENTIAL_ID")
        if not self.credential_id:
            raise TetherError(
                "credential_id is required. Provide it directly or set "
                "TETHER_CREDENTIAL_ID environment variable"
            )
        
        # Get private key from parameters or environment
        if private_key_path is None and private_key_pem is None and private_key_der is None:
            env_key_path = os.getenv("TETHER_PRIVATE_KEY_PATH")
            if env_key_path:
                private_key_path = env_key_path
            else:
                raise TetherError(
                    "A private key is required. Provide private_key_path, "
                    "private_key_pem, private_key_der, or set "
                    "TETHER_PRIVATE_KEY_PATH environment variable"
                )
        
        # Load the private key
        self.private_key = load_private_key(
            key_path=private_key_path,
            key_pem=private_key_pem,
            key_der=private_key_der
        )
        
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        
        # Create HTTP client
        self._client = httpx.Client(timeout=timeout)
    
    def __enter__(self) -> "TetherClient":
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
    
    def close(self) -> None:
        """Close the HTTP client."""
        self._client.close()
    
    def request_challenge(self) -> str:
        """
        Request a verification challenge from the Tether API.
        
        Returns:
            str: The challenge code to sign
            
        Raises:
            TetherAPIError: If the API request fails
        """
        try:
            response = self._client.post(f"{self.base_url}/challenge")
            response.raise_for_status()
            
            data = response.json()
            if "code" not in data:
                raise TetherAPIError(
                    "Invalid challenge response: missing 'code' field",
                    response.status_code,
                    response.text
                )
            
            return data["code"]
            
        except httpx.HTTPStatusError as e:
            raise TetherAPIError(
                f"Challenge request failed: {e.response.status_code}",
                e.response.status_code,
                e.response.text
            )
        except httpx.RequestError as e:
            raise TetherAPIError(f"Challenge request failed: {e}")
    
    def sign(self, challenge: str) -> str:
        """
        Sign a challenge with the private key.
        
        Args:
            challenge: The challenge string to sign
            
        Returns:
            str: The signature as URL-safe base64 (no padding)
        """
        return sign_challenge(self.private_key, challenge)
    
    def submit_proof(self, challenge: str, proof: str) -> VerificationResult:
        """
        Submit a signed challenge for verification.
        
        Args:
            challenge: The original challenge string
            proof: The signature of the challenge
            
        Returns:
            VerificationResult: The verification result
            
        Raises:
            TetherAPIError: If the API request fails
            TetherVerificationError: If verification fails
        """
        try:
            payload = {
                "challenge": challenge,
                "proof": proof,
                "credentialId": self.credential_id
            }
            
            response = self._client.post(
                f"{self.base_url}/challenge/verify",
                json=payload
            )
            response.raise_for_status()
            
            data = response.json()
            
            if not data.get("valid", False):
                error_msg = data.get("error", "Verification failed")
                return VerificationResult(
                    verified=False,
                    error=error_msg,
                    challenge=challenge
                )
            
            # Parse registered_since if present
            registered_since = None
            if "registeredSince" in data:
                try:
                    registered_since = datetime.fromisoformat(
                        data["registeredSince"].replace('Z', '+00:00')
                    )
                except (ValueError, TypeError):
                    pass  # Ignore invalid date formats
            
            return VerificationResult(
                verified=True,
                agent_name=data.get("agentName"),
                verify_url=data.get("verifyUrl"),
                email=data.get("email"),
                registered_since=registered_since,
                challenge=challenge
            )
            
        except httpx.HTTPStatusError as e:
            raise TetherAPIError(
                f"Verification request failed: {e.response.status_code}",
                e.response.status_code,
                e.response.text
            )
        except httpx.RequestError as e:
            raise TetherAPIError(f"Verification request failed: {e}")
    
    def verify(self) -> VerificationResult:
        """
        Perform complete verification in one call.
        
        This combines request_challenge(), sign(), and submit_proof().
        
        Returns:
            VerificationResult: The verification result
            
        Raises:
            TetherAPIError: If any API request fails
            TetherVerificationError: If verification fails
        """
        try:
            # Step 1: Request challenge
            challenge = self.request_challenge()
            
            # Step 2: Sign the challenge
            proof = self.sign(challenge)
            
            # Step 3: Submit proof
            return self.submit_proof(challenge, proof)
            
        except Exception as e:
            if isinstance(e, (TetherAPIError, TetherVerificationError)):
                raise
            raise TetherError(f"Verification failed: {e}")