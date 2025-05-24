from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os
from pathlib import Path

class CryptoManager:
    # This class is responsible for encrypting and decrypting data, primarily for sensitive
    # information like stored credentials or configurations if needed.
    # It uses AES-256-CBC, which is a strong symmetric encryption algorithm.
    
    def __init__(self):
        self.key_file = Path("config/secret.key") # Path to the file where the encryption key is stored.
        # The key is loaded or generated upon initialization and kept in memory.
        # For higher security, key management services or hardware security modules (HSMs) would be better,
        # but for a local tool, a file-based key is a common approach.
        self._key = self._load_or_generate_key()
        
    def _load_or_generate_key(self) -> bytes:
        # Attempts to load the encryption key from self.key_file.
        # If the file doesn't exist or is empty, a new key is generated, saved, and then used.
        try:
            if self.key_file.exists() and self.key_file.stat().st_size > 0:
                with open(self.key_file, 'r') as f: # Open in text mode as key is base64 encoded string
                    key_b64 = f.read().strip()
                    if not key_b64: # Double check if strip resulted in empty
                        # This case should ideally be caught by st_size > 0, but as a safeguard:
                        raise ValueError("Key file was empty after reading.")
                    return base64.b64decode(key_b64) # Decode from base64 to get the raw bytes
            else:
                # Key file doesn't exist or is empty, so generate a new one.
                if not self.key_file.parent.exists():
                    self.key_file.parent.mkdir(parents=True, exist_ok=True) 
                
                new_key_b64 = self.generate_key() # Generate a new key (base64 encoded string)
                new_key_bytes = base64.b64decode(new_key_b64) # Decode it for use
                
                # Save the new key (base64 encoded string) to the file.
                # Set restrictive permissions if on a POSIX system for security.
                # os.umask(0o077) # Temporarily set umask for file creation - maybe too complex for this stage
                with open(self.key_file, 'w') as f:
                    f.write(new_key_b64)
                # if os.name == 'posix': # Try to set file permissions to be readable only by user
                #     os.chmod(self.key_file, 0o600)
                return new_key_bytes
        except ValueError as ve: # Catch specific error for empty key file
             raise RuntimeError(f"Encryption key error: {ve}")
        except Exception as e:
            # Broad exception catch for other issues like permission errors, etc.
            raise RuntimeError(f"Could not load or generate encryption key: {e}")

    @staticmethod
    def generate_key() -> str:
        # Generates a new 256-bit (32 bytes) AES key and returns it as a base64 encoded string.
        # AES-256 requires a 32-byte key.
        key_bytes = get_random_bytes(32) 
        return base64.b64encode(key_bytes).decode('utf-8') # Encode to base64 string for easy storage/display
        
    def encrypt(self, data: str) -> str:
        # Encrypts the input string `data`.
        # Returns a base64 encoded string representing the IV + encrypted ciphertext.
        if not isinstance(data, str):
            raise TypeError("Data to encrypt must be a string.")
        try:
            data_bytes = data.encode('utf-8') # Convert string to bytes
            iv = get_random_bytes(AES.block_size) # Generate a random Initialization Vector (IV)
            
            cipher = AES.new(self._key, AES.MODE_CBC, iv) # Create AES cipher object in CBC mode
            
            # Pad the data to be a multiple of the block size (AES block size is 16 bytes)
            padded_data = pad(data_bytes, AES.block_size)
            encrypted_data_bytes = cipher.encrypt(padded_data)
            
            # Prepend the IV to the ciphertext. The IV is needed for decryption.
            combined_bytes = iv + encrypted_data_bytes
            
            # Return as a base64 encoded string for easier handling/storage.
            return base64.b64encode(combined_bytes).decode('utf-8')
            
        except Exception as e:
            # Log or handle specific encryption errors if necessary
            raise Exception(f"Encryption error: {str(e)}") # Re-raise as a generic Exception for now
            
    def decrypt(self, encrypted_data_b64: str) -> str:
        # Decrypts the base64 encoded input string `encrypted_data_b64`.
        # Assumes the input string contains the IV prepended to the actual ciphertext.
        if not isinstance(encrypted_data_b64, str):
            raise TypeError("Encrypted data must be a base64 encoded string.")
        try:
            # Decode the base64 input to get the raw bytes (IV + ciphertext)
            encrypted_bytes_combined = base64.b64decode(encrypted_data_b64.encode('utf-8'))
            
            # Extract the IV (it's the first AES.block_size bytes, typically 16 bytes)
            iv = encrypted_bytes_combined[:AES.block_size]
            # The rest is the actual ciphertext
            ciphertext = encrypted_bytes_combined[AES.block_size:]
            
            cipher = AES.new(self._key, AES.MODE_CBC, iv) # Recreate the AES cipher object with the same key and IV
            
            decrypted_padded_bytes = cipher.decrypt(ciphertext) # Decrypt the data
            # Unpad the decrypted data to get the original plaintext bytes
            decrypted_data_bytes = unpad(decrypted_padded_bytes, AES.block_size)
            
            return decrypted_data_bytes.decode('utf-8') # Convert bytes back to string
            
        except (ValueError, KeyError) as e: # Common errors during base64 decode or unpadding
            raise Exception(f"Decryption error: Invalid data or key. {str(e)}")
        except Exception as e:
            # Log or handle specific decryption errors
            raise Exception(f"Decryption error: {str(e)}") # Re-raise as a generic Exception