from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os

class CryptoManager:
    """Handles encryption/decryption of sensitive data"""
    
    def __init__(self):
        # In production, this should be loaded from environment variables or secure storage
        # For this implementation, we'll use a static key
        self._key = base64.b64decode("VE4yNHdCeTZQY1RaYVduSDJwUmtGZEx4RWJNcTlMM2o=")  # 32 bytes for AES-256
        
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
            # Generate random IV
            iv = get_random_bytes(AES.block_size)
            
            # Create cipher
            cipher = AES.new(self._key, AES.MODE_CBC, iv)
            
            # Pad and encrypt
            padded_data = pad(data.encode(), AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            # Combine IV and encrypted data
            combined = iv + encrypted_data
            
            # Return as base64
            return base64.b64encode(combined).decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Encryption error: {str(e)}")
            
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt AES-256-CBC encrypted data
        Expects base64 encoded input
        """
        try:
            # Decode from base64
            encrypted_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
            
            # Extract IV and ciphertext
            iv = encrypted_bytes[:AES.block_size]
            ciphertext = encrypted_bytes[AES.block_size:]
            
            # Create cipher
            cipher = AES.new(self._key, AES.MODE_CBC, iv)
            
            # Decrypt and unpad
            decrypted_padded = cipher.decrypt(ciphertext)
            decrypted_data = unpad(decrypted_padded, AES.block_size)
            
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Decryption error: {str(e)}") 