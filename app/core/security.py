import hashlib
import base64
import json
import os
from typing import Dict, Any
from cryptography.fernet import Fernet
from app.core.config import settings
from app.core.dte import CloudSecretDTE

class HoneyEncryption:  
    def __init__(self):
        self.dte = CloudSecretDTE()

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        derived = hashlib.scrypt(
            password.encode(),
            salt=salt,
            n=settings.KDF_N,
            r=settings.KDF_R,
            p=settings.KDF_P,
            dklen=settings.KDF_DKLEN,
        )
        return base64.urlsafe_b64encode(derived)

    def _salt_from_vault(self, vault: Dict[str, Any]) -> bytes:
        """
        Retrieves the salt from the vault.
        If the salt is missing or invalid, this will cause a failure
        downstream, which is the intended secure behavior.
        """
        salt_b64 = vault.get("salt")
        return base64.urlsafe_b64decode(salt_b64.encode())

    def encrypt(self, data: Dict[str, Any], password: str) -> Dict[str, Any]:
        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        cipher = Fernet(key)

        plaintext = json.dumps(data).encode()
        encrypted_data = cipher.encrypt(plaintext).decode()

        base_seed = int.from_bytes(os.urandom(8), "big")
        fake_secrets = self.dte.sample_multiple(settings.FAKE_KEY_COUNT, base_seed)
        fake_keys = [item["aws_api_key"] for item in fake_secrets]

        return {
            "ciphertext": encrypted_data,
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "fake_keys": fake_keys,
            "fake_secrets": fake_secrets,
            "metadata": {
                "hint": "valid_api_keys_present",
                "scheme": "HE+DTE+Sinkhole",
                "version": "2"
            }
        }

    def decrypt(self, vault: Dict[str, Any], password: str) -> Dict[str, Any]:
        try:
            salt = self._salt_from_vault(vault)
            key = self._derive_key(password, salt)
            cipher = Fernet(key)

            decrypted = cipher.decrypt(vault["ciphertext"].encode())
            real_data = json.loads(decrypted.decode())

            return {
                "status": "real",
                "data": real_data
            }
        except Exception:
            # Any exception during decryption (missing salt, bad password, etc.)
            # results in returning a fake secret.
            fake_data = self._select_fake(vault, password)
            return {
                "status": "fake",
                "data": fake_data
            }

    def _select_fake(self, vault: Dict[str, Any], password: str) -> Dict[str, Any]:
        fake_secrets = vault.get("fake_secrets", [])
        if fake_secrets:
            index = self._stable_index(password, len(fake_secrets))
            return fake_secrets[index]

        fake_keys = vault.get("fake_keys", [])
        if fake_keys:
            index = self._stable_index(password, len(fake_keys))
            return {
                "aws_api_key": fake_keys[index],
                "service": "s3",
                "region": "us-east-1",
                "access_scope": "read-only",
            }

        seed = int(hashlib.sha256(password.encode()).hexdigest(), 16)
        return self.dte.sample_secret(seed)

    def _stable_index(self, password: str, size: int) -> int:
        hash_val = int(hashlib.sha256(password.encode()).hexdigest(), 16)
        return hash_val % size