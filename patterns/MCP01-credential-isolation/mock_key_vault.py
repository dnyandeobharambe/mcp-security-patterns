"""
Mock Key Vault for local development.
Replace with Azure Key Vault in production.

Production code:
    from azure.keyvault.secrets import SecretClient
    from azure.identity import DefaultAzureCredential
    client = SecretClient(vault_url=VAULT_URL, credential=DefaultAzureCredential())
    secret = client.get_secret("api-key").value
"""

import os
from typing import Optional


class MockKeyVault:
    """
    Simulates Azure Key Vault for local development.
    Secrets stored in memory — never in environment variables passed to agent.
    """

    def __init__(self):
        # In production: these come from Azure Key Vault
        # In local dev: these come from .env but are NEVER passed to agent context
        self._secrets = {
            "device-api-key": os.getenv("MOCK_API_KEY", "mock-key-local-dev-only"),
            "erp-api-key": os.getenv("MOCK_ERP_KEY", "mock-erp-key-local-dev-only"),
            "database-password": os.getenv("MOCK_DB_PASS", "mock-db-pass-local-dev-only"),
        }

    async def get_secret(self, secret_name: str) -> Optional[str]:
        """
        Retrieve a secret by name.
        Called at tool execution time — never at agent initialization.
        """
        secret = self._secrets.get(secret_name)
        if not secret:
            raise ValueError(f"Secret '{secret_name}' not found in vault")
        return secret


def get_key_vault():
    """
    Factory function — returns real or mock Key Vault based on config.
    """
    use_mock = os.getenv("USE_MOCK_KEY_VAULT", "true").lower() == "true"

    if use_mock:
        print("[KeyVault] Using mock Key Vault for local development")
        return MockKeyVault()
    else:
        # Production: Azure Key Vault
        from azure.keyvault.secrets import SecretClient
        from azure.identity import DefaultAzureCredential

        vault_url = os.getenv("AZURE_KEY_VAULT_URL")
        if not vault_url:
            raise ValueError("AZURE_KEY_VAULT_URL not set")

        print(f"[KeyVault] Using Azure Key Vault: {vault_url}")
        return SecretClient(
            vault_url=vault_url,
            credential=DefaultAzureCredential()
        )
