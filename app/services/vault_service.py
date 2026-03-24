from app.core.security import HoneyEncryption
from app.models.vault import VaultModel
from app.db.mongo import mongo
from bson import ObjectId

class VaultService:
    def __init__(self):
        self.he = HoneyEncryption()

    def _collection(self):
        # Resolve the collection lazily so imports do not require an active DB connection.
        return mongo.get_database()["vaults"]

    async def create_vault(self, aws_api_key: str, password: str) -> dict:
        data = {"aws_api_key": aws_api_key}
        vault_data = self.he.encrypt(data, password)
        vault = VaultModel(**vault_data)
        
        # Exclude the _id field (None) so MongoDB can auto-generate it
        vault_dict = vault.model_dump(by_alias=True, exclude={'id'})
        
        collection = self._collection()
        result = await collection.insert_one(vault_dict)

        return {
            "vault_id": str(result.inserted_id),
            "vault": vault_data
        }

    async def get_vault(self, vault_id: str) -> dict | None:
        try:
            obj_id = ObjectId(vault_id)
        except Exception:
            return None # Invalid ObjectId format

        vault = await self._collection().find_one({"_id": obj_id})
        if not vault:
            return None

        vault["_id"] = str(vault["_id"])
        return vault

    def decrypt_vault(self, vault: dict, password: str) -> dict:
        return self.he.decrypt(vault, password)