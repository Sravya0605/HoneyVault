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

    def _derive_seed(self, password: str, salt: bytes) -> int:
        return int(
            hashlib.sha256(password.encode() + salt).hexdigest(),
            16
        )

    def encrypt(self, data: Dict[str, Any], password: str) -> Dict[str, Any]:
        salt = os.urandom(16)

        key = self._derive_key(password, salt)
        cipher = Fernet(key)

        plaintext = json.dumps(data).encode()
        ciphertext = cipher.encrypt(plaintext).decode()

        real_seed = self._derive_seed(password, salt)

        return {
            "ciphertext": ciphertext,
            "salt": base64.urlsafe_b64encode(salt).decode(),
            "real_seed": str(real_seed),
            "metadata": {
                "scheme": "HE_DTE_SEEDED",
                "version": "4"
            }
        }

    def decrypt(self, vault: Dict[str, Any], password: str) -> Dict[str, Any]:
        salt = base64.urlsafe_b64decode(vault["salt"].encode())

        key = self._derive_key(password, salt)
        cipher = Fernet(key)

        seed = self._derive_seed(password, salt)

        # Always compute fake
        fake = self.dte.sample_secret(seed)

        # Check if correct password
        if str(seed) == vault.get("real_seed"):
            try:
                decrypted = cipher.decrypt(vault["ciphertext"].encode())
                real_data = json.loads(decrypted.decode())
                return {"status": "real", "data": real_data}
            except:
                # fallback safety (should not happen)
                return {"status": "fake", "data": fake}

        return {"status": "fake", "data": fake}