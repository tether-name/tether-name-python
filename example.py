#!/usr/bin/env python3
"""
Example usage of the Tether.name Python SDK.

This demonstrates the API without hitting the live service.
"""

import tempfile
from pathlib import Path
from tether_name import TetherClient, generate_test_keypair
from tether_name.crypto import load_private_key, sign_challenge


def main():
    print("🚀 Tether.name Python SDK Example")
    print("=" * 40)
    
    # Generate a test keypair for demonstration
    print("\n1️⃣  Generating test RSA-2048 keypair...")
    private_key, public_key_pem = generate_test_keypair()
    print(f"   ✅ Generated {private_key.key_size}-bit RSA key")
    
    # Save the key to a temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f:
        # Write private key in PEM format
        from cryptography.hazmat.primitives import serialization
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        f.write(private_key_pem)
        temp_key_path = f.name
    
    print(f"   📁 Saved key to: {temp_key_path}")
    
    # Test loading key from different formats
    print("\n2️⃣  Testing key loading...")
    
    # From file path
    loaded_key1 = load_private_key(key_path=temp_key_path)
    print("   ✅ Loaded from file path")
    
    # From PEM string
    loaded_key2 = load_private_key(key_pem=private_key_pem)
    print("   ✅ Loaded from PEM string")
    
    # Test signing
    print("\n3️⃣  Testing challenge signing...")
    challenge = "example-challenge-uuid-12345"
    signature = sign_challenge(private_key, challenge)
    print(f"   📝 Challenge: {challenge}")
    print(f"   ✍️  Signature: {signature[:32]}...{signature[-8:]}")
    print(f"   📏 Signature length: {len(signature)} characters")
    
    # Test TetherClient initialization
    print("\n4️⃣  Testing TetherClient initialization...")
    try:
        client = TetherClient(
            agent_id="test-agent-id",
            private_key_path=temp_key_path
        )
        print("   ✅ TetherClient initialized successfully")
        
        # Test signing through client
        client_signature = client.sign(challenge)
        print(f"   ✍️  Client signature: {client_signature[:32]}...{client_signature[-8:]}")
        
        client.close()
        
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    # Cleanup
    Path(temp_key_path).unlink()
    
    print("\n🎉 All tests completed successfully!")
    print("\n📚 To use with real Tether agents:")
    print("   1. Register at https://tether.name")
    print("   2. Download your private key")
    print("   3. Set TETHER_AGENT_ID and TETHER_PRIVATE_KEY_PATH")
    print("   4. Call client.verify() to get verified identity")


if __name__ == "__main__":
    main()