from app.core.security import HoneyEncryption
from app.models.vault import VaultModel
from app.db.mongo import mongo
from bson import ObjectId
import hmac
import hashlib


class CredentialRegistry:
    """
    Maintains set of valid real credentials.
    Used to distinguish between real and fake decoded outputs (post-decryption).
    
    SECURITY: Stores HMAC(api_key, server_secret) instead of plaintext keys.
    This prevents full credential disclosure if MongoDB is breached.
    """
    
    # Server secret for HMAC (in production: load from environment/vault)
    _SERVER_SECRET = b"honey-vault-server-secret-change-in-production"
    
    def _collection(self):
        return mongo.get_database()["real_credentials"]
    
    @staticmethod
    def _compute_key_hmac(api_key: str) -> str:
        """Compute HMAC of api_key for storage."""
        h = hmac.new(CredentialRegistry._SERVER_SECRET, api_key.encode(), hashlib.sha256)
        return h.hexdigest()
    
    async def add_credential(self, api_key: str) -> None:
        """Register a real credential (store HMAC, not plaintext)."""
        collection = self._collection()
        key_hmac = self._compute_key_hmac(api_key)
        
        await collection.update_one(
            {"key_hmac": key_hmac},
            {"$set": {"key_hmac": key_hmac, "added_at": __import__('datetime').datetime.utcnow()}},
            upsert=True
        )
    
    async def is_real(self, api_key: str) -> bool:
        """Check if credential is real by comparing HMACs."""
        collection = self._collection()
        key_hmac = self._compute_key_hmac(api_key)
        result = await collection.find_one({"key_hmac": key_hmac})
        return result is not None
    
    async def remove_credential(self, api_key: str) -> None:
        """Deregister a credential (revoke)."""
        collection = self._collection()
        key_hmac = self._compute_key_hmac(api_key)
        await collection.delete_one({"key_hmac": key_hmac})


class VaultService:
    def __init__(self):
        self.he = HoneyEncryption()
        self.registry = CredentialRegistry()

    def _collection(self):
        return mongo.get_database()["vaults"]

    async def create_vault(self, aws_api_key: str, password: str) -> dict:
        """
        Create vault with real credential.
        
        Steps:
        1. Register credential in registry
        2. Encrypt credential → vault
        3. Store vault (no real_seed, no hash)
        
        Note: Encrypted seed is stored, not the key itself.
        """
        # Prepare message for encryption
        message = {"aws_api_key": aws_api_key}
        
        # Register this as a real credential
        await self.registry.add_credential(aws_api_key)
        
        # Encrypt using HE scheme
        vault_data = self.he.encrypt(message, password)
        
        # Create vault model (no real_seed or hash anymore)
        vault = VaultModel(
            ciphertext=vault_data["ciphertext"],
            salt=vault_data["salt"],
            nonce=vault_data["nonce"],
            tag=vault_data["tag"],
            metadata=vault_data["metadata"]
        )
        vault_dict = vault.model_dump(by_alias=True, exclude={'id'})
        
        collection = self._collection()
        result = await collection.insert_one(vault_dict)
        
        return {
            "vault_id": str(result.inserted_id),
            "vault": vault_data
        }

    async def get_vault(self, vault_id: str) -> dict | None:
        """Retrieve vault by ID."""
        try:
            obj_id = ObjectId(vault_id)
        except:
            return None

        vault = await self._collection().find_one({"_id": obj_id})
        if not vault:
            return None

        vault["_id"] = str(vault["_id"])
        return vault

    async def decrypt_vault(self, vault: dict, password: str) -> dict:
        """
        Decrypt vault with any password.
        
        Returns:
        {
            "status": "decrypted",
            "data": {decoded message},
            "is_real": bool or None
        }
        
        Post-processing: check is_real via credential registry.
        """
        result = self.he.decrypt(vault, password)
        
        # Determine if decoded credential is real
        if isinstance(result.get("data"), dict):
            api_key = result["data"].get("aws_api_key")
            if api_key:
                is_real = await self.registry.is_real(api_key)
                result["is_real"] = is_real
        
        return result