"""
Tether.name SDK - Official Python client for AI agent identity verification.

Tether lets AI agents cryptographically prove their identity using RSA-2048 
digital signatures. This package provides a simple interface to the Tether.name API.

Example:
    >>> from tether_name import TetherClient
    >>> client = TetherClient(
    ...     agent_id="your-agent-id",
    ...     private_key_path="/path/to/key.pem"
    ... )
    >>> result = client.verify()
    >>> if result.verified:
    ...     print(f"Verified as {result.agent_name}")
"""

from .client import Agent, Domain, TetherClient, VerificationResult
from .crypto import load_private_key, sign_challenge, generate_test_keypair
from .exceptions import (
    TetherError,
    TetherAPIError, 
    TetherVerificationError,
    TetherKeyError
)

__version__ = "2.0.1"
__author__ = "Commit 451"
__email__ = "python@tether.name"
__homepage__ = "https://tether.name"

__all__ = [
    # Main classes
    "TetherClient",
    "VerificationResult",
    "Agent",
    "Domain",
    
    # Crypto functions
    "load_private_key",
    "sign_challenge", 
    "generate_test_keypair",
    
    # Exceptions
    "TetherError",
    "TetherAPIError",
    "TetherVerificationError", 
    "TetherKeyError",
    
    # Metadata
    "__version__",
    "__author__",
    "__email__",
    "__homepage__",
]