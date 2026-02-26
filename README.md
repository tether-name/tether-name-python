# Tether.name Python SDK

[![PyPI](https://img.shields.io/pypi/v/tether-name)](https://pypi.org/project/tether-name/)
[![Python versions](https://img.shields.io/pypi/pyversions/tether-name.svg)](https://pypi.org/project/tether-name/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Official Python SDK for [Tether.name](https://tether.name) — cryptographic identity verification for AI agents.**

Tether lets AI agents prove their identity using RSA-2048 digital signatures, providing a secure, verifiable way to establish trust in AI-to-AI and AI-to-human interactions.

## 🚀 Quick Start

### Installation

```bash
pip install tether-name
```

### Basic Usage

```python
from tether_name import TetherClient

# Initialize with your credentials
client = TetherClient(
    credential_id="your-credential-id",
    private_key_path="/path/to/your/private-key.der"
)

# Verify your agent's identity
result = client.verify()

if result.verified:
    print(f"✅ Verified as: {result.agent_name}")
    print(f"📧 Email: {result.email}")
    print(f"🔗 Verification URL: {result.verify_url}")
else:
    print(f"❌ Verification failed: {result.error}")
```

### Agent Management

One line to start managing agents programmatically:

```python
from tether_name import TetherClient

client = TetherClient(api_key="tether_sk_...")

# Create, list, and delete agents
agent = client.create_agent("my-bot")
agents = client.list_agents()
client.delete_agent(agent.id)
```

## 📖 How Tether Works

Tether.name provides cryptographic identity verification for AI agents through a simple 3-step process:

1. **Register**: Create an agent identity at [tether.name](https://tether.name) and get your credential ID and RSA-2048 private key
2. **Sign**: Your agent signs a cryptographic challenge using its private key  
3. **Verify**: The signature proves your agent's identity to others

This creates unforgeable digital identity that anyone can verify.

## 🔧 Configuration

### Authentication

The SDK supports two authentication modes:

**API Key** — for agent management (create, list, delete):

```python
client = TetherClient(api_key="tether_sk_...")
```

**Private Key** — for identity verification (sign, verify):

```python
client = TetherClient(
    credential_id="your-credential-id",
    private_key_path="/path/to/key.der"
)
```

**Both** — for full access:

```python
client = TetherClient(
    api_key="tether_sk_...",
    credential_id="your-credential-id",
    private_key_path="/path/to/key.der"
)
```

### Environment Variables

Set these environment variables to avoid hardcoding credentials:

```bash
export TETHER_API_KEY="tether_sk_..."
export TETHER_CREDENTIAL_ID="your-credential-id"
export TETHER_PRIVATE_KEY_PATH="/path/to/your/key.der"
```

Then initialize without parameters:

```python
client = TetherClient()  # Uses environment variables
```

### Key Formats

The SDK supports multiple private key formats:

```python
# From file path (PEM or DER)
client = TetherClient(
    credential_id="...",
    private_key_path="/path/to/key.der"
)

# From PEM string
client = TetherClient(
    credential_id="...",
    private_key_pem="-----BEGIN PRIVATE KEY-----\n..."
)

# From DER bytes  
with open("key.der", "rb") as f:
    key_bytes = f.read()

client = TetherClient(
    credential_id="...",
    private_key_der=key_bytes
)
```

## 📚 API Reference

### `TetherClient`

Main client for Tether.name API interactions.

#### Constructor

```python
TetherClient(
    credential_id: Optional[str] = None,
    private_key_path: Optional[Union[str, Path]] = None,
    private_key_pem: Optional[Union[str, bytes]] = None,
    private_key_der: Optional[bytes] = None,
    base_url: str = "https://api.tether.name",
    timeout: float = 30.0,
    api_key: Optional[str] = None
)
```

| Parameter | Env var | Description |
|---|---|---|
| `api_key` | `TETHER_API_KEY` | API key for agent management operations |
| `credential_id` | `TETHER_CREDENTIAL_ID` | Credential ID for identity verification |
| `private_key_path` | `TETHER_PRIVATE_KEY_PATH` | Path to RSA-2048 private key (PEM or DER) |
| `private_key_pem` | — | PEM-encoded private key string |
| `private_key_der` | — | DER-encoded private key bytes |

When `api_key` is set, `credential_id` and private key parameters become optional (only needed for verify/sign operations).

#### Methods

##### `verify() -> VerificationResult`

Perform complete identity verification in one call.

```python
result = client.verify()
print(result.verified)      # bool: True if verified
print(result.agent_name)    # str: Your agent's display name
print(result.verify_url)    # str: Public verification URL
print(result.email)         # str: Registered email address
```

##### `request_challenge() -> str`

Request a cryptographic challenge from Tether.

```python
challenge = client.request_challenge()
print(challenge)  # "550e8400-e29b-41d4-a716-446655440000"
```

##### `sign(challenge: str) -> str`

Sign a challenge with your private key.

```python
challenge = client.request_challenge()
signature = client.sign(challenge)
print(signature)  # URL-safe base64 signature (no padding)
```

##### `submit_proof(challenge: str, proof: str) -> VerificationResult`

Submit signed challenge for verification.

```python
challenge = client.request_challenge()
signature = client.sign(challenge)
result = client.submit_proof(challenge, signature)
```

##### `create_agent(agent_name: str, description: str = "") -> Agent`

Create a new agent. Requires API key authentication.

```python
agent = client.create_agent("my-bot", description="My automated agent")
print(agent.id)                # Agent ID
print(agent.agent_name)        # "my-bot"
print(agent.registration_token) # Token for agent registration
```

##### `list_agents() -> list[Agent]`

List all agents. Requires API key authentication.

```python
agents = client.list_agents()
for agent in agents:
    print(f"{agent.agent_name} (created {agent.created_at})")
```

##### `delete_agent(agent_id: str) -> bool`

Delete an agent. Requires API key authentication.

```python
client.delete_agent("agent-id-here")
```

### `Agent`

Agent object returned by management operations.

```python
@dataclass
class Agent:
    id: str                        # Unique agent ID
    agent_name: str                # Agent display name
    description: str               # Agent description
    created_at: int                # Creation time (epoch ms)
    registration_token: str = ""   # Token for agent registration
    last_verified_at: int = 0      # Last verification time (epoch ms)
```

### `VerificationResult`

Result object returned by verification operations.

```python
@dataclass
class VerificationResult:
    verified: bool                           # True if verification succeeded
    agent_name: Optional[str] = None         # Agent's display name
    verify_url: Optional[str] = None         # Public verification URL
    email: Optional[str] = None              # Registered email
    registered_since: Optional[datetime] = None  # Registration date
    error: Optional[str] = None              # Error message if failed
    challenge: Optional[str] = None          # Original challenge
```

## 🔐 Step-by-Step Example

For more control, you can break down the verification process:

```python
from tether_name import TetherClient, TetherAPIError, TetherVerificationError

try:
    client = TetherClient(
        credential_id="your-credential-id",
        private_key_path="/path/to/key.der"
    )
    
    # Step 1: Request a challenge
    print("📡 Requesting challenge...")
    challenge = client.request_challenge()
    print(f"🔢 Challenge: {challenge}")
    
    # Step 2: Sign the challenge  
    print("✍️  Signing challenge...")
    signature = client.sign(challenge)
    print(f"📝 Signature: {signature[:32]}...")
    
    # Step 3: Submit proof
    print("📤 Submitting proof...")
    result = client.submit_proof(challenge, signature)
    
    if result.verified:
        print(f"✅ Successfully verified as {result.agent_name}")
        print(f"🔗 Share this verification: {result.verify_url}")
    else:
        print(f"❌ Verification failed: {result.error}")
        
except TetherAPIError as e:
    print(f"🌐 API Error: {e.message}")
    if e.status_code:
        print(f"📊 Status: {e.status_code}")
        
except TetherVerificationError as e:
    print(f"🔒 Verification Error: {e.message}")
    
finally:
    client.close()  # Clean up HTTP connections
```

## 🧪 Testing

The SDK includes comprehensive unit tests that don't hit the live API:

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=tether_name
```

## 🔗 Context Manager Support

Use TetherClient as a context manager for automatic cleanup:

```python
with TetherClient(credential_id="...", private_key_path="...") as client:
    result = client.verify()
    print(f"Verified: {result.verified}")
# HTTP client automatically closed
```

## 🛡️ Security Notes

- **Private Key Security**: Never commit private keys to version control or share them publicly
- **API Key Security**: API keys are hashed before storage. The `tether_sk_` prefix enables leak detection. Revoke compromised keys immediately
- **Key Format**: Tether requires RSA-2048 keys. Other key sizes will be rejected
- **Challenge Uniqueness**: Each verification uses a unique challenge to prevent replay attacks
- **Signature Algorithm**: Uses SHA256withRSA (PKCS#1 v1.5 padding) as specified by Tether

## 🐛 Error Handling

The SDK provides specific exception types for different error conditions:

```python
from tether_name import (
    TetherError,           # Base exception
    TetherAPIError,        # API request failures  
    TetherVerificationError,  # Verification failures
    TetherKeyError,        # Private key issues
)

try:
    result = client.verify()
except TetherAPIError as e:
    # Handle API connectivity or server errors
    print(f"API Error {e.status_code}: {e.message}")
except TetherVerificationError as e:
    # Handle verification failures (invalid signature, etc.)
    print(f"Verification failed: {e.message}")
except TetherKeyError as e:
    # Handle private key loading or format errors
    print(f"Key error: {e.message}")
except TetherError as e:
    # Handle any other Tether-related errors
    print(f"Tether error: {e.message}")
```

## 📋 Requirements

- **Python**: 3.8+
- **Dependencies**: `httpx>=0.20.0`, `cryptography>=3.4.0`
- **Key Format**: RSA-2048 private key (PEM or DER)

## 📦 Publishing

Published to PyPI automatically via GitHub Actions when a release is created (uses trusted publishing).

### Version checklist

Update the version in:

1. `pyproject.toml` → `version`
2. `src/tether_name/__init__.py` → `__version__`

### Steps

1. Update version numbers above (they must match)
2. Commit and push to `main`
3. Create a GitHub release with a matching tag (e.g. `v1.0.0`)
4. CI builds and publishes to PyPI automatically

### Manual publish (if needed)

```bash
pip install build twine
python -m build
twine upload dist/*
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions welcome! Please see the [GitHub repository](https://github.com/tether-name/tether-name-python) for details.

## 🔗 Links

- **🌐 Tether.name**: [https://tether.name](https://tether.name)  
- **📦 PyPI Package**: [https://pypi.org/project/tether-name/](https://pypi.org/project/tether-name/)
- **💻 Source Code**: [https://github.com/tether-name/tether-name-python](https://github.com/tether-name/tether-name-python)
- **📖 API Documentation**: [https://docs.tether.name](https://docs.tether.name)
- **❓ Support**: [jawnnypoo@gmail.com](mailto:jawnnypoo@gmail.com)

---

**Ready to get started?** Register your AI agent at [tether.name](https://tether.name) and start building with cryptographic identity verification! 🚀