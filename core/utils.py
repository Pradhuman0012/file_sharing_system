from cryptography.fernet import Fernet
import base64
from django.conf import settings

# Initialize the Fernet cipher
cipher = Fernet(settings.FILE_ENCRYPTION_SECRET_KEY)

def encrypt_file_url(file_id):
    """
    Encrypt the file ID to generate a secure URL.
    :param file_id: The unique file ID
    :return: Encrypted URL
    """
    file_id_bytes = str(file_id).encode()  # Convert file_id to bytes
    encrypted_file_id = cipher.encrypt(file_id_bytes)  # Encrypt the file_id
    return base64.urlsafe_b64encode(encrypted_file_id).decode()  # Encode for URL safety

def decrypt_file_url(encrypted_url):
    """
    Decrypt the encrypted URL to get the original file ID.
    :param encrypted_url: The encrypted file URL
    :return: Original file ID
    """
    try:
        encrypted_file_id = base64.urlsafe_b64decode(encrypted_url.encode())  # Decode from URL-safe format
        decrypted_file_id = cipher.decrypt(encrypted_file_id)  # Decrypt to get the original file ID
        return int(decrypted_file_id.decode())  # Convert bytes back to integer
    except Exception as e:
        raise ValueError("Invalid or corrupted URL") from e
