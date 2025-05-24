from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os
from pathlib import Path

class CryptoManager:
    """Handles encryption/decryption of sensitive data"""
    
    def __init__(self):
        self.key_file = Path("config/secret.key")
        self._key = self._load_or_generate_key()
        
    def _load_or_generate_key(self) -> bytes:
        """Load key from file, or generate and save if not exists."""
        try:
            if self.key_file.exists():
                with open(self.key_file, 'r') as f:
                    key_b64 = f.read().strip()
                    if not key_b64:
                        raise ValueError("Key file is empty.")
                    return base64.b64decode(key_b64)
            else:
                self.key_file.parent.mkdir(parents=True, exist_ok=True) 
                new_key_b64 = self.generate_key()
                new_key_bytes = base64.b64decode(new_key_b64)
                with open(self.key_file, 'w') as f:
                    f.write(new_key_b64)
                return new_key_bytes
        except Exception as e:
            raise RuntimeError(f"Could not load or generate encryption key: {e}")

    @staticmethod
    def generate_key():
        """Generate a new AES key"""
        return base64.b64encode(get_random_bytes(32)).decode('utf-8')
        
    def encrypt(self, data: str) -> str:
        """
        Encrypt data using AES-256-CBC
        Returns base64 encoded encrypted data
        """
        try:
            iv = get_random_bytes(AES.block_size)
            
            cipher = AES.new(self._key, AES.MODE_CBC, iv)
            
            padded_data = pad(data.encode(), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            combined = iv + encrypted_data
            
            return base64.b64encode(combined).decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Encryption error: {str(e)}")
            
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt AES-256-CBC encrypted data
        Expects base64 encoded input
        """
        try:
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            iv = encrypted_bytes[:AES.block_size]
            ciphertext = encrypted_bytes[AES.block_size:]
            
            cipher = AES.new(self._key, AES.MODE_CBC, iv)
            
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Decryption error: {str(e)}")