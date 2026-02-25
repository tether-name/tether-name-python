"""
Tether.name SDK exceptions.
"""

from typing import Optional


class TetherError(Exception):
    """Base exception for all Tether.name SDK errors."""
    
    def __init__(self, message: str, details: Optional[str] = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details


class TetherAPIError(TetherError):
    """Exception raised when the Tether.name API returns an error."""
    
    def __init__(
        self, 
        message: str, 
        status_code: Optional[int] = None,
        response_text: Optional[str] = None
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.response_text = response_text


class TetherVerificationError(TetherError):
    """Exception raised when verification fails."""
    
    def __init__(self, message: str, challenge: Optional[str] = None) -> None:
        super().__init__(message)
        self.challenge = challenge


class TetherKeyError(TetherError):
    """Exception raised when there's an issue with the private key."""
    pass