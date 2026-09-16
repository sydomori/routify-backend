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
            return jsonify({"error": "Password change required", "code": "password_change_required"}),403
        return fn(*args, **kwargs)

    return wrapper

class TestDeactivateDriverRoute:
    def test_manager_can_deactivate_driver(self, client, manager, driver, auth_headers):
        response = client.patch(f"/api/auth/drivers/{driver.id}/deactivate", headers=auth_headers(manager))
        assert response.status_code == 200

    def test_deactivated_driver_cannot_log_in(self, client, manager, driver, auth_headers):
        client.patch(f"/api/auth/drivers/{driver.id}/deactivate", headers=auth_headers(manager))
        response = client.post("/api/auth/login", json={"identifier": driver.phone, "password": "DriverPass123"})
        assert response.status_code == 401

    def test_driver_cannot_deactivate_another_driver(self, client, driver, auth_headers):
        response = client.patch(f"/api/auth/drivers/{driver.id}/deactivate", headers=auth_headers(driver))
        assert response.status_code == 403

    def test_unknown_driver_id_returns_404(self, client, manager, auth_headers):
        response = client.patch("/api/auth/drivers/99999/deactivate", headers=auth_headers(manager))
        assert response.status_code == 404

    def test_cannot_deactivate_a_manager_via_this_route(self, client, manager, make_user, auth_headers):
        other_manager = make_user(role="manager")
        response = client.patch(f"/api/auth/drivers/{other_manager.id}/deactivate", headers=auth_headers(manager))
        assert response.status_code == 400