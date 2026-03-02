"""Client-level tests for TetherClient HTTP interactions."""

import json
from unittest.mock import patch, MagicMock
import pytest
from cryptography.hazmat.primitives import serialization

from tether_name.client import TetherClient, Agent, Domain, VerificationResult
from tether_name.exceptions import TetherAPIError, TetherVerificationError
from tether_name.crypto import generate_test_keypair


@pytest.fixture
def keypair(tmp_path):
    """Generate a temporary RSA key pair for testing."""
    private_key, public_pem = generate_test_keypair()
    # Serialize private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    key_file = tmp_path / "test-key.pem"
    key_file.write_text(private_pem)
    return str(key_file), private_pem, public_pem


@pytest.fixture
def client(keypair):
    """Create a TetherClient with test agent identity."""
    key_path, _, _ = keypair
    return TetherClient(
        agent_id="test-agent-id",
        private_key_path=key_path,
    )


@pytest.fixture
def api_client(keypair):
    """Create a TetherClient with API key for management operations."""
    key_path, _, _ = keypair
    return TetherClient(
        agent_id="test-agent-id",
        private_key_path=key_path,
        api_key="test-api-key",
    )


def mock_response(data, status_code=200):
    """Create a mock httpx.Response using a real httpx.Response."""
    import httpx
    content = json.dumps(data).encode()
    response = httpx.Response(
        status_code=status_code,
        content=content,
        headers={"content-type": "application/json"},
        request=httpx.Request("GET", "http://test"),
    )
    return response


class TestRequestChallenge:
    def test_posts_to_challenge_endpoint(self, client):
        with patch.object(client._client, "post", return_value=mock_response({"code": "test-uuid"})) as mock_post:
            code = client.request_challenge()
            
            assert code == "test-uuid"
            mock_post.assert_called_once()
            url = mock_post.call_args[0][0]
            assert url.endswith("/challenge")

    def test_raises_on_missing_code(self, client):
        with patch.object(client._client, "post", return_value=mock_response({})):
            with pytest.raises(TetherAPIError, match="missing"):
                client.request_challenge()

    def test_raises_on_http_error(self, client):
        with patch.object(client._client, "post", return_value=mock_response({"error": "rate limited"}, 429)):
            with pytest.raises(TetherAPIError):
                client.request_challenge()


class TestSubmitProof:
    def test_posts_proof_with_agent_id(self, client):
        resp_data = {
            "valid": True,
            "agentName": "Test Agent",
            "verifyUrl": "https://tether.name/check?challenge=abc",
        }
        with patch.object(client._client, "post", return_value=mock_response(resp_data)) as mock_post:
            result = client.submit_proof("challenge-code", "proof-sig")
            
            assert result.verified is True
            assert result.agent_name == "Test Agent"
            assert result.verify_url == "https://tether.name/check?challenge=abc"
            
            # Check request body
            call_kwargs = mock_post.call_args
            body = call_kwargs[1].get("json") or json.loads(call_kwargs[1].get("content", "{}"))
            assert body["challenge"] == "challenge-code"
            assert body["proof"] == "proof-sig"
            assert body["agentId"] == "test-agent-id"

    def test_raises_on_http_error(self, client):
        with patch.object(client._client, "post", return_value=mock_response({"error": "bad"}, 401)):
            with pytest.raises(TetherAPIError):
                client.submit_proof("c", "p")


class TestVerify:
    def test_full_verify_flow(self, client):
        """verify() should request challenge, sign it, and submit proof."""
        call_count = 0
        
        def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # requestChallenge
                return mock_response({"code": "verify-challenge"})
            else:
                # submitProof
                return mock_response({
                    "valid": True,
                    "agentName": "My Agent",
                    "verifyUrl": "https://tether.name/check?challenge=verify-challenge",
                })
        
        with patch.object(client._client, "post", side_effect=mock_post):
            result = client.verify()
            
            assert result.verified is True
            assert result.agent_name == "My Agent"
            assert call_count == 2

    def test_returns_unverified_result_on_invalid_signature(self, client):
        """verify() returns VerificationResult with verified=False, doesn't raise."""
        call_count = 0
        
        def mock_post(url, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_response({"code": "fail-challenge"})
            else:
                return mock_response({"valid": False, "error": "Invalid signature"})
        
        with patch.object(client._client, "post", side_effect=mock_post):
            result = client.verify()
            assert result.verified is False


class TestCreateAgent:
    def test_posts_to_agents_issue(self, api_client):
        resp_data = {
            "id": "agent-123",
            "agentName": "New Bot",
            "description": "A test bot",
            "domainId": "domain-123",
            "createdAt": 1700000000000,
            "registrationToken": "reg-token-xyz",
        }
        with patch.object(api_client._client, "post", return_value=mock_response(resp_data)) as mock_post:
            agent = api_client.create_agent("New Bot", "A test bot", "domain-123")
            
            assert agent.id == "agent-123"
            assert agent.agent_name == "New Bot"
            assert agent.registration_token == "reg-token-xyz"
            assert agent.domain_id == "domain-123"
            
            url = mock_post.call_args[0][0]
            assert "/agents/issue" in url

            payload = mock_post.call_args[1].get("json", {})
            assert payload.get("domainId") == "domain-123"
            
            # Check auth header
            headers = mock_post.call_args[1].get("headers", {})
            assert headers.get("Authorization") == "Bearer test-api-key"

    def test_sends_unauthenticated_without_api_key(self, client):
        """Without API key, management methods send unauthenticated (server returns 401)."""
        with patch.object(client._client, "post", return_value=mock_response({"error": "Unauthorized"}, 401)):
            with pytest.raises(TetherAPIError):
                client.create_agent("bot")

    def test_raises_on_http_error(self, api_client):
        with patch.object(api_client._client, "post", return_value=mock_response({"error": "Unauthorized"}, 401)):
            with pytest.raises(TetherAPIError):
                api_client.create_agent("bot")


class TestListAgents:
    def test_gets_agents(self, api_client):
        agents_data = [
            {"id": "a1", "agentName": "Bot 1", "description": "", "createdAt": 1700000000000, "domainId": "d1", "domain": "example.com"},
            {"id": "a2", "agentName": "Bot 2", "description": "helper", "createdAt": 1700000001000},
        ]
        with patch.object(api_client._client, "get", return_value=mock_response(agents_data)) as mock_get:
            agents = api_client.list_agents()
            
            assert len(agents) == 2
            assert agents[0].agent_name == "Bot 1"
            assert agents[0].domain_id == "d1"
            assert agents[0].domain == "example.com"
            assert agents[1].agent_name == "Bot 2"
            
            url = mock_get.call_args[0][0]
            assert "/agents" in url
            
            headers = mock_get.call_args[1].get("headers", {})
            assert headers.get("Authorization") == "Bearer test-api-key"

    def test_sends_unauthenticated_without_api_key(self, client):
        """Without API key, list_agents sends unauthenticated (server returns 401)."""
        with patch.object(client._client, "get", return_value=mock_response({"error": "Unauthorized"}, 401)):
            with pytest.raises(TetherAPIError):
                client.list_agents()


class TestListDomains:
    def test_gets_domains(self, api_client):
        domains_data = [
            {"id": "d1", "domain": "example.com", "verified": True, "verifiedAt": 1700000000000, "lastCheckedAt": 1700001000000, "createdAt": 1699999000000},
            {"id": "d2", "domain": "example.org", "verified": False, "verifiedAt": 0, "lastCheckedAt": 0, "createdAt": 1699998000000},
        ]
        with patch.object(api_client._client, "get", return_value=mock_response(domains_data)) as mock_get:
            domains = api_client.list_domains()

            assert len(domains) == 2
            assert domains[0].domain == "example.com"
            assert domains[0].verified is True
            assert domains[1].domain == "example.org"

            url = mock_get.call_args[0][0]
            assert "/domains" in url

            headers = mock_get.call_args[1].get("headers", {})
            assert headers.get("Authorization") == "Bearer test-api-key"

    def test_sends_unauthenticated_without_api_key(self, client):
        """Without API key, list_domains sends unauthenticated (server returns 401)."""
        with patch.object(client._client, "get", return_value=mock_response({"error": "Unauthorized"}, 401)):
            with pytest.raises(TetherAPIError):
                client.list_domains()


class TestDeleteAgent:
    def test_deletes_agent(self, api_client):
        resp = mock_response({})
        resp.status_code = 200
        with patch.object(api_client._client, "delete", return_value=resp) as mock_del:
            result = api_client.delete_agent("agent-to-delete")
            
            assert result is True
            
            url = mock_del.call_args[0][0]
            assert "/agents/agent-to-delete" in url
            
            headers = mock_del.call_args[1].get("headers", {})
            assert headers.get("Authorization") == "Bearer test-api-key"

    def test_raises_on_404(self, api_client):
        with patch.object(api_client._client, "delete", return_value=mock_response({"error": "Not found"}, 404)):
            with pytest.raises(TetherAPIError):
                api_client.delete_agent("nonexistent")

    def test_sends_unauthenticated_without_api_key(self, client):
        """Without API key, delete_agent sends unauthenticated (server returns 401)."""
        with patch.object(client._client, "delete", return_value=mock_response({"error": "Unauthorized"}, 401)):
            with pytest.raises(TetherAPIError):
                client.delete_agent("any-id")


class TestErrorHandling:
    def test_wraps_network_error(self, client):
        import httpx
        with patch.object(client._client, "post", side_effect=httpx.ConnectError("Connection refused")):
            with pytest.raises(TetherAPIError, match="failed"):
                client.request_challenge()
