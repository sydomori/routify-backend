from functools import wraps

from flask import jsonify
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt

from app.auth.service import get_user_by_id
from app.auth.exceptions import UserNotFoundError

def role_required(*allowed_roles):
    """
    checks the role claim embedded in the JWT
    role doesn't expire at runtime thus the lifecycle is safe thus easier to check from the token than from an extra d query every time
    """

    def decorator(fn):
        @wraps(fn) #copy original function name onto wrapper
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt()
            if claims.get("role") not in allowed_roles:
                return jsonify({"error": "Forbidden: insufficient role"}), 403
            return fn(*args, **kwargs)

        return wrapper

    return decorator

def password_change_required(fn):
    """
    enforces hard gate for drivers with temporary passwords ie they cant access anything
    deliberately re-reads must_change_password from db rather than trusting the JWT as the token would stay stale for its full lifecycle
    even after the DB bool flips to false
    """

    @wraps(fn)
    def wrapper(*args,**kwargs):
        verify_jwt_in_request()
        try:
            user= get_user_by_id(int(get_jwt_identity()))
        except UserNotFoundError:
            return jsonify({"error":"User not found"}), 404

        if user.must_change_password:
            return jsonify({"error": "Password change required", "code": "password_change_required"}),404
        return fn(*args, **kwargs)

    return wrapper