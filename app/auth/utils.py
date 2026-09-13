import re
import secrets
import string

import bcrypt

#exclude characters that are easily confused with each other
_TEMP_PASSWORD_ALPHABET = "".join(
    c for c in (string.ascii_letters + string.digits) if c not in "0O1lI"
)

_PHONE_RE = re.compile(r"^\+?[1-9]\d{7,14}$")


def hash_password(
    plain_password:str
) -> str:
    """hash a pain text password using bcrypt and return a utf-8 encoded string for storage"""
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")

def verify_password(
    plain_password:str,
    password_hash:str
) -> bool:
    """Checks plaintext password against password hash"""
    if not plain_password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False

def generate_temp_password(
    length:int = 8
) -> str:
    """Generate a random temporary password of specified length"""
    return ''.join(secrets.choice(_TEMP_PASSWORD_ALPHABET) for _ in range(length))