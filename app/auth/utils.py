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