import os
import base64
import bcrypt
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


def derive_key(secret_key, salt):
    """Derive a 32-byte key from the secret key and salt using HKDF."""
    info = b"FileEncryption"
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=info, backend=default_backend())
    return hkdf.derive(salt + secret_key) 

def encrypt_file(file_path, key):
    logging.info(f"Encrypting file: {file_path}")
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        salt = get_random_bytes(16) 
        derived_key = derive_key(key, salt) 

        original_file_name = os.path.basename(file_path).encode()
        encrypted_name_hash = bcrypt.hashpw(original_file_name, bcrypt.gensalt())
        encrypted_name_prefix = base64.urlsafe_b64encode(
        salt + encrypted_name_hash).decode('utf-8')

        new_file_name = f"{encrypted_name_prefix}.lock3d" 
        new_file_path = os.path.join(os.path.dirname(file_path), new_file_name)

        original_file_name_length = len(original_file_name)
        nonce = get_random_bytes(12)
        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(
            original_file_name_length.to_bytes(2, 'big') + 
            original_file_name + 
            data
        )
        combined_data = '|'.join([
            base64.b64encode(salt).decode('utf-8'),
            base64.b64encode(nonce).decode('utf-8'),
            base64.b64encode(tag).decode('utf-8'),
            base64.b64encode(ciphertext).decode('utf-8'), 
        ])

        with open(new_file_path, 'w') as f:
            f.write(combined_data)

        os.remove(file_path)
        logging.info(f"{os.path.basename(file_path)} encrypted to {new_file_name}")

    except Exception as e:
        logging.error(f"Failed to encrypt file {file_path}: {e}")

def decrypt_file(file_path, key):
    logging.info(f"Decrypting file: {file_path}")
    try:
        with open(file_path, 'r') as f:
            combined_data = f.read()

        salt_b64, nonce_b64, tag_b64, ciphertext_b64 = combined_data.split("|")
        
        salt = base64.b64decode(salt_b64.encode())
        nonce = base64.b64decode(nonce_b64.encode())
        tag = base64.b64decode(tag_b64.encode())
        ciphertext = base64.b64decode(ciphertext_b64.encode())

        derived_key = derive_key(key, salt)

        cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)

        try:
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as e:
            logging.error(f"Decryption failed for {file_path}. Possible corruption or incorrect key/salt: {e}")
            return 

        original_file_name_length = int.from_bytes(decrypted_data[:2], 'big')
        original_file_name = decrypted_data[2:2 + original_file_name_length].decode()
        data = decrypted_data[2 + original_file_name_length:]

        original_file_path = os.path.join(os.path.dirname(file_path), original_file_name)
        with open(original_file_path, 'wb') as f:
            f.write(data)

        os.remove(file_path)
        logging.info(f"{os.path.basename(file_path)} decrypted to {original_file_name}")

    except Exception as e:
        logging.error(f"Failed to decrypt file {file_path}: {e}")
