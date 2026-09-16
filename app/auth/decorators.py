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


class TestInviteManagerRoute:
    def test_manager_can_invite_manager(self, client, manager, auth_headers):
        response = client.post(
            "/api/auth/invite-manager",
            json={"name": "Second", "phone": "+254700000002", "email": "second@routify.test"},
            headers=auth_headers(manager),
        )
        assert response.status_code == 201
        assert response.get_json()["must_change_password"] is True

    def test_driver_cannot_invite_manager(self, client, driver, auth_headers):
        response = client.post(
            "/api/auth/invite-manager",
            json={"name": "Second", "phone": "+254700000002", "email": "second@routify.test"},
            headers=auth_headers(driver),
        )
        assert response.status_code == 403

    def test_requires_authentication(self, client):
        response = client.post(
            "/api/auth/invite-manager",
            json={"name": "Second", "phone": "+254700000002", "email": "second@routify.test"},
        )
        assert response.status_code == 401

    def test_duplicate_email_returns_409(self, client, manager, auth_headers):
        response = client.post(
            "/api/auth/invite-manager",
            json={"name": "Dupe", "phone": "+254700000009", "email": manager.email},
            headers=auth_headers(manager),
        )
        assert response.status_code == 409

    def test_invalid_email_returns_400(self, client, manager, auth_headers):
        response = client.post(
            "/api/auth/invite-manager",
            json={"name": "Bad Email", "phone": "+254700000002", "email": "not-an-email"},
            headers=auth_headers(manager),
        )
        assert response.status_code == 400

class TestAcceptInviteRoute:
    def _invite_and_get_token(self, manager, invitee_email="second@routify.test"):
        from app.auth import service
        invitee = service.invite_manager(
            name="Second", phone="+254700000002", email=invitee_email, requesting_user=manager
        )
        return service._generate_invite_token(invitee.id)

    def test_valid_token_succeeds(self, client, manager):
        token = self._invite_and_get_token(manager)
        response = client.post("/api/auth/accept-invite", json={"token": token, "new_password": "NewManagerPass1"})
        assert response.status_code == 200

    def test_does_not_return_an_access_token(self, client, manager):
        token = self._invite_and_get_token(manager)
        response = client.post("/api/auth/accept-invite", json={"token": token, "new_password": "NewManagerPass1"})
        assert "access_token" not in response.get_json()

    def test_invitee_can_log_in_afterward(self, client, manager):
        token = self._invite_and_get_token(manager)
        client.post("/api/auth/accept-invite", json={"token": token, "new_password": "NewManagerPass1"})
        response = client.post("/api/auth/login", json={"identifier": "second@routify.test", "password": "NewManagerPass1"})
        assert response.status_code == 200

    def test_garbage_token_returns_400(self, client):
        response = client.post("/api/auth/accept-invite", json={"token": "garbage", "new_password": "NewManagerPass1"})
        assert response.status_code == 400

    def test_reused_token_returns_400(self, client, manager):
        token = self._invite_and_get_token(manager)
        client.post("/api/auth/accept-invite", json={"token": token, "new_password": "FirstPass1"})
        response = client.post("/api/auth/accept-invite", json={"token": token, "new_password": "SecondPass1"})
        assert response.status_code == 400

    def test_is_a_public_route_no_auth_header_needed(self, client, manager):
        token = self._invite_and_get_token(manager)
        # Deliberately no Authorization header at all.
        response = client.post("/api/auth/accept-invite", json={"token": token, "new_password": "NewManagerPass1"})
        assert response.status_code == 200


class TestMeRoute:
    def test_returns_current_user(self, client, driver, auth_headers):
        response = client.get("/api/auth/me", headers=auth_headers(driver))
        assert response.status_code == 200
        assert response.get_json()["id"] == driver.id

    def test_requires_authentication(self, client):
        response = client.get("/api/auth/me")
        assert response.status_code == 401

    def test_never_includes_password_hash(self, client, manager, auth_headers):
        response = client.get("/api/auth/me", headers=auth_headers(manager))
        assert "password_hash" not in response.get_json()