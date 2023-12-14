import os
import jwt
import base64
import datetime
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class CryptoStore:

    def __init__(self) -> None:
        self._private_key = None
        self._public_key = None
    
    def generate_keys(self, key_size=2048) -> None:
        self._private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size, # 2048 o 4096
            backend=default_backend()
        )
        self._public_key = self._private_key.public_key()
    
    def load_private_key(self, file: str = 'private_key.pem') -> None:
        with open(file, "rb") as key_file:
            self._private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        self._public_key = self._private_key.public_key()
    
    def save_private_key(self, file: str = 'private_key.pem') -> str:
        private_pem = self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(file, 'wb') as f:
            f.write(private_pem)
    
    def load_public_key(self, file: str = 'public_key.pem') -> None:
        with open("public_key.pem", "rb") as key_file:
            self._public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
    
    def save_public_key(self, file: str = 'public_key.pem') -> None:
        public_pem = self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(file, 'wb') as f:
            f.write(public_pem)


class TokenValidate:

    def __init__(self, store: CryptoStore) -> None:
        self._store = store

    def generate_signed_token(self, time: int = 300, data: dict = {}) -> str:
        if not self._store._private_key:
            raise Exception("Private key not loaded.")

        payload = {
            **data,
            "valid": True,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(seconds=time)
        }
        return jwt.encode(payload, self._store._private_key, algorithm='RS256')
    
    def verify_signed_token(self, token) -> dict:
        if not self._store._public_key:
            raise Exception("Public key not loaded.")

        try:
            return jwt.decode(token, self._store._public_key, algorithms=['RS256'])
        except jwt.ExpiredSignatureError:
            return {"valid": False, "message": "Token is expired."}
        except jwt.InvalidTokenError:
            return {"valid": False, "message": "Token is invalid."}


class TokenEncrypt:

    @staticmethod
    def _pad(key: str) -> str:
        if len(key) > 16:
            raise ValueError("Key too long.") # (16 bytes for AES-128)
        return key.ljust(16, '\0')
    
    def encrypt_token(self, token: str, key: str) -> str:
        key = self._pad(key).encode()
        iv = os.urandom(16)

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(token.encode()) + padder.finalize()

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv + ct).decode('utf-8')

    def decrypt_token(self, token: str, key: str) -> str:
        key = self._pad(key).encode()
        token = base64.b64decode(token.encode())
        iv = token[:16]
        ct = token[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_token = decryptor.update(ct) + decryptor.finalize()
        
        unpadder = padding.PKCS7(128).unpadder()
        try:
            token = unpadder.update(padded_token) + unpadder.finalize()
            return token.decode('utf-8')
        except ValueError:
            return None
