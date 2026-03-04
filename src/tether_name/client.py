"""
Tether.name SDK client for agent identity verification.
"""
from __future__ import annotations


import os
from dataclasses import dataclass
from datetime import datetime, timezone
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
    domain: Optional[str] = None
    registered_since: Optional[datetime] = None
    error: Optional[str] = None
    challenge: Optional[str] = None


@dataclass
class Agent:
    """A Tether.name agent."""

    id: str
    agent_name: str
    description: str
    domain_id: str = ""
    domain: Optional[str] = None
    created_at: int = 0  # epoch ms
    registration_token: str = ""
    last_verified_at: int = 0


@dataclass
class Domain:
    """A domain claimed under a Tether account."""

    id: str
    domain: str
    verified: bool
    verified_at: int = 0
    last_checked_at: int = 0
    created_at: int = 0


@dataclass
class UpdateAgentResult:
    """Result of updating which identity an agent shows on verification."""

    id: str
    domain_id: str = ""
    domain: Optional[str] = None
    message: str = ""


@dataclass
class AgentKey:
    """Agent key lifecycle entry."""

    id: str
    status: str
    created_at: int
    activated_at: int
    grace_until: int
    revoked_at: int
    revoked_reason: str = ""


@dataclass
class RotateKeyResult:
    """Result of rotating an agent key."""

    agent_id: str
    previous_key_id: Optional[str]
    new_key_id: str
    grace_until: int
    message: str


@dataclass
class RevokeKeyResult:
    """Result of revoking an agent key."""

    agent_id: str
    key_id: str
    revoked: bool
    promoted_key_id: Optional[str]
    message: str


class TetherClient:
    """
    Client for interacting with the Tether.name API.
    
    Example:
        >>> client = TetherClient(
        ...     agent_id="your-agent-id",
        ...     private_key_path="/path/to/key.pem"
        ... )
        >>> result = client.verify()
        >>> if result.verified:
        ...     print(f"Verified as {result.agent_name}")
    """
    
    def __init__(
        self,
        agent_id: Optional[str] = None,
        private_key_path: Optional[Union[str, Path]] = None,
        private_key_pem: Optional[Union[str, bytes]] = None,
        private_key_der: Optional[bytes] = None,
        timeout: float = 30.0,
        api_key: Optional[str] = None,
    ) -> None:
        """
        Initialize the Tether client.

        Args:
            agent_id: Your Tether agent ID (or set TETHER_AGENT_ID)
            private_key_path: Path to private key file (or set TETHER_PRIVATE_KEY_PATH)
            private_key_pem: Private key as PEM string/bytes
            private_key_der: Private key as DER bytes
            timeout: Request timeout in seconds
            api_key: API key for management operations (or set TETHER_API_KEY)

        Raises:
            TetherError: If required parameters are missing or invalid
        """
        # Get API key from parameter or environment
        self.api_key = api_key or os.getenv("TETHER_API_KEY") or None

        # Get agent ID from parameter or environment
        self.agent_id = agent_id or os.getenv("TETHER_AGENT_ID") or None

        # Get private key from parameters or environment
        has_private_key = (
            private_key_path is not None
            or private_key_pem is not None
            or private_key_der is not None
            or os.getenv("TETHER_PRIVATE_KEY_PATH")
        )

        if self.api_key:
            # API key mode: agent_id and private_key are optional
            self.private_key: Optional[RSAPrivateKey] = None
            if has_private_key:
                if private_key_path is None and private_key_pem is None and private_key_der is None:
                    private_key_path = os.getenv("TETHER_PRIVATE_KEY_PATH")
                self.private_key = load_private_key(
                    key_path=private_key_path,
                    key_pem=private_key_pem,
                    key_der=private_key_der
                )
        else:
            # No API key: require agent_id and private_key (existing behavior)
            if not self.agent_id:
                raise TetherError(
                    "agent_id is required. Provide it directly or set "
                    "TETHER_AGENT_ID environment variable"
                )

            if not has_private_key:
                raise TetherError(
                    "A private key is required. Provide private_key_path, "
                    "private_key_pem, private_key_der, or set "
                    "TETHER_PRIVATE_KEY_PATH environment variable"
                )

            if private_key_path is None and private_key_pem is None and private_key_der is None:
                private_key_path = os.getenv("TETHER_PRIVATE_KEY_PATH")

            self.private_key = load_private_key(
                key_path=private_key_path,
                key_pem=private_key_pem,
                key_der=private_key_der
            )

        self.base_url = 'https://api.tether.name'
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

    def _auth_headers(self) -> dict[str, str]:
        """Return authorization headers for API key authenticated requests."""
        if self.api_key:
            return {"Authorization": f"Bearer {self.api_key}"}
        return {}

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

        Raises:
            TetherError: If no private key is available
        """
        if self.private_key is None:
            raise TetherError(
                "Private key is required for signing. Provide private_key_path "
                "or private_key_der when creating the client."
            )
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
                "agentId": self.agent_id
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
            
            # Parse registered_since if present (epoch ms or ISO string)
            registered_since = None
            if "registeredSince" in data:
                try:
                    raw = data["registeredSince"]
                    if isinstance(raw, (int, float)):
                        registered_since = datetime.fromtimestamp(
                            raw / 1000.0, tz=timezone.utc
                        )
                    elif isinstance(raw, str):
                        registered_since = datetime.fromisoformat(
                            raw.replace('Z', '+00:00')
                        )
                except (ValueError, TypeError, OSError):
                    pass  # Ignore invalid date formats
            
            return VerificationResult(
                verified=True,
                agent_name=data.get("agentName"),
                verify_url=data.get("verifyUrl"),
                email=data.get("email"),
                domain=data.get("domain"),
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

    def create_agent(self, agent_name: str, description: str = "", domain_id: str = "") -> Agent:
        """
        Create a new agent.

        Requires API key or JWT auth.

        Args:
            agent_name: Name for the agent
            description: Optional description
            domain_id: Optional verified domain ID to assign to this agent

        Returns:
            Agent: The newly created agent

        Raises:
            TetherAPIError: If the API request fails
        """
        try:
            payload = {"agentName": agent_name, "description": description}
            if domain_id:
                payload["domainId"] = domain_id

            response = self._client.post(
                f"{self.base_url}/agents/issue",
                json=payload,
                headers=self._auth_headers()
            )
            response.raise_for_status()

            data = response.json()
            return Agent(
                id=data["id"],
                agent_name=data["agentName"],
                description=data.get("description", ""),
                domain_id=data.get("domainId", ""),
                created_at=data["createdAt"],
                registration_token=data.get("registrationToken", "")
            )

        except httpx.HTTPStatusError as e:
            raise TetherAPIError(
                f"Create agent failed: {e.response.status_code}",
                e.response.status_code,
                e.response.text
            )
        except httpx.RequestError as e:
            raise TetherAPIError(f"Create agent failed: {e}")

    def list_agents(self) -> list[Agent]:
        """
        List all agents.

        Requires API key or JWT auth.

        Returns:
            list[Agent]: All agents

        Raises:
            TetherAPIError: If the API request fails
        """
        try:
            response = self._client.get(
                f"{self.base_url}/agents",
                headers=self._auth_headers()
            )
            response.raise_for_status()

            data = response.json()
            return [Agent(
                id=c["id"],
                agent_name=c["agentName"],
                description=c.get("description", ""),
                domain_id=c.get("domainId", ""),
                domain=c.get("domain"),
                created_at=c.get("createdAt", c.get("issuedAt", 0)),
                last_verified_at=c.get("lastVerifiedAt", 0)
            ) for c in data]

        except httpx.HTTPStatusError as e:
            raise TetherAPIError(
                f"List agents failed: {e.response.status_code}",
                e.response.status_code,
                e.response.text
            )
        except httpx.RequestError as e:
            raise TetherAPIError(f"List agents failed: {e}")

    def list_domains(self) -> list[Domain]:
        """
        List all registered domains for the authenticated account.

        Requires API key or JWT auth.

        Returns:
            list[Domain]: All domains

        Raises:
            TetherAPIError: If the API request fails
        """
        try:
            response = self._client.get(
                f"{self.base_url}/domains",
                headers=self._auth_headers()
            )
            response.raise_for_status()

            data = response.json()
            return [Domain(
                id=d["id"],
                domain=d["domain"],
                verified=d.get("verified", False),
                verified_at=d.get("verifiedAt", 0),
                last_checked_at=d.get("lastCheckedAt", 0),
                created_at=d.get("createdAt", 0),
            ) for d in data]

        except httpx.HTTPStatusError as e:
            raise TetherAPIError(
                f"List domains failed: {e.response.status_code}",
                e.response.status_code,
                e.response.text
            )
        except httpx.RequestError as e:
            raise TetherAPIError(f"List domains failed: {e}")

    def delete_agent(self, agent_id: str) -> bool:
        """
        Delete an agent.

        Requires API key or JWT auth.

        Args:
            agent_id: ID of the agent to delete

        Returns:
            bool: True if the agent was deleted successfully

        Raises:
            TetherAPIError: If the API request fails
        """
        try:
            response = self._client.delete(
                f"{self.base_url}/agents/{agent_id}",
                headers=self._auth_headers()
            )
            response.raise_for_status()
            return response.status_code == 200

        except httpx.HTTPStatusError as e:
            raise TetherAPIError(
                f"Delete agent failed: {e.response.status_code}",
                e.response.status_code,
                e.response.text
            )
        except httpx.RequestError as e:
            raise TetherAPIError(f"Delete agent failed: {e}")

    def update_agent_domain(self, agent_id: str, domain_id: str = "") -> UpdateAgentResult:
        """
        Update which identity is shown when an agent is verified.

        Requires API key or JWT auth.

        Args:
            agent_id: ID of the agent to update
            domain_id: Verified domain ID to show; pass empty string to show account email

        Returns:
            UpdateAgentResult: Updated identity-display settings

        Raises:
            TetherAPIError: If the API request fails
        """
        try:
            response = self._client.patch(
                f"{self.base_url}/agents/{agent_id}",
                json={"domainId": domain_id},
                headers=self._auth_headers(),
            )
            response.raise_for_status()

            data = response.json()
            return UpdateAgentResult(
                id=data["id"],
                domain_id=data.get("domainId", ""),
                domain=data.get("domain"),
                message=data.get("message", ""),
            )
        except httpx.HTTPStatusError as e:
            raise TetherAPIError(
                f"Update agent failed: {e.response.status_code}",
                e.response.status_code,
                e.response.text,
            )
        except httpx.RequestError as e:
            raise TetherAPIError(f"Update agent failed: {e}")

    def list_agent_keys(self, agent_id: str) -> list[AgentKey]:
        """List key lifecycle entries for an agent."""
        try:
            response = self._client.get(
                f"{self.base_url}/agents/{agent_id}/keys",
                headers=self._auth_headers(),
            )
            response.raise_for_status()

            data = response.json()
            return [
                AgentKey(
                    id=k["id"],
                    status=k.get("status", ""),
                    created_at=k.get("createdAt", 0),
                    activated_at=k.get("activatedAt", 0),
                    grace_until=k.get("graceUntil", 0),
                    revoked_at=k.get("revokedAt", 0),
                    revoked_reason=k.get("revokedReason", ""),
                )
                for k in data
            ]
        except httpx.HTTPStatusError as e:
            raise TetherAPIError(
                f"List agent keys failed: {e.response.status_code}",
                e.response.status_code,
                e.response.text,
            )
        except httpx.RequestError as e:
            raise TetherAPIError(f"List agent keys failed: {e}")

    def rotate_agent_key(
        self,
        agent_id: str,
        public_key: str,
        grace_period_hours: int = 24,
        reason: str = "",
        *,
        step_up_code: str = "",
        challenge: str = "",
        proof: str = "",
    ) -> RotateKeyResult:
        """Rotate an agent public key with step-up authentication inputs."""
        payload = {
            "publicKey": public_key,
            "gracePeriodHours": grace_period_hours,
        }
        if reason:
            payload["reason"] = reason
        if step_up_code:
            payload["stepUpCode"] = step_up_code
        if challenge:
            payload["challenge"] = challenge
        if proof:
            payload["proof"] = proof

        try:
            response = self._client.post(
                f"{self.base_url}/agents/{agent_id}/keys/rotate",
                json=payload,
                headers=self._auth_headers(),
            )
            response.raise_for_status()
            data = response.json()
            return RotateKeyResult(
                agent_id=data["agentId"],
                previous_key_id=data.get("previousKeyId"),
                new_key_id=data["newKeyId"],
                grace_until=data.get("graceUntil", 0),
                message=data.get("message", ""),
            )
        except httpx.HTTPStatusError as e:
            raise TetherAPIError(
                f"Rotate agent key failed: {e.response.status_code}",
                e.response.status_code,
                e.response.text,
            )
        except httpx.RequestError as e:
            raise TetherAPIError(f"Rotate agent key failed: {e}")

    def revoke_agent_key(
        self,
        agent_id: str,
        key_id: str,
        reason: str = "",
        *,
        step_up_code: str = "",
        challenge: str = "",
        proof: str = "",
    ) -> RevokeKeyResult:
        """Revoke an agent key with step-up authentication inputs."""
        payload: dict[str, str] = {}
        if reason:
            payload["reason"] = reason
        if step_up_code:
            payload["stepUpCode"] = step_up_code
        if challenge:
            payload["challenge"] = challenge
        if proof:
            payload["proof"] = proof

        try:
            response = self._client.post(
                f"{self.base_url}/agents/{agent_id}/keys/{key_id}/revoke",
                json=payload,
                headers=self._auth_headers(),
            )
            response.raise_for_status()
            data = response.json()
            return RevokeKeyResult(
                agent_id=data["agentId"],
                key_id=data["keyId"],
                revoked=bool(data.get("revoked", False)),
                promoted_key_id=data.get("promotedKeyId"),
                message=data.get("message", ""),
            )
        except httpx.HTTPStatusError as e:
            raise TetherAPIError(
                f"Revoke agent key failed: {e.response.status_code}",
                e.response.status_code,
                e.response.text,
            )
        except httpx.RequestError as e:
            raise TetherAPIError(f"Revoke agent key failed: {e}")
