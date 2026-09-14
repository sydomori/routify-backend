from functools import wraps

from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt

from auth.service import get_user_by_id
from auth.exceptions import UserNotFoundError

def role_required(*allowed_roles):
    """
    checks the role claim embedded in the JWT
    role doesn't expire at runtime thus the lifecycle is safe thus easier to check from the token than from an extra d query every time
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get("role") not in allowed_roles:
                return jsonify({"error": "Forbidden: insufficient role"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator