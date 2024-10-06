import hashlib
import time
import uuid
import bcrypt
import base64

import secrets
import string

region_id = "us-west-1"


def encode_base62(num):
    chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    base = len(chars)
    encoded = []
    while num > 0:
        num, rem = divmod(num, base)
        encoded.append(chars[rem])
    return ''.join(encoded[::-1])


def generate_shortURL_code():
    # Combine region_id, current time, and a random uuid
    unique_input = f"{time.time()}_{uuid.uuid4()}_{region_id}"

    # Hash the combination to generate a unique string
    unique_hash = hashlib.sha256(unique_input.encode()).digest()
    num = int.from_bytes(unique_hash, 'big') % (62**8)  # Reduce collision risk
    # Encoding with base-62
    short_code = encode_base62(num).zfill(8)  # Ensure 8 characters

    return short_code


def generate_api_key(length: int = 32) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def hash_password(password):
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())
