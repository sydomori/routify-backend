class TestBootstrapManagerRoute:
    def test_succeeds_with_zero_managers(self, client):
        response = client.post(
            "/api/auth/bootstrap-manager",
            json={"name": "Root", "phone": "+254700000001", "email": "root@routify.test", "password": "RootPass123"},
        )
        assert response.status_code == 201
        body = response.get_json()
        assert body["must_change_password"] is False
        assert "password_hash" not in body

    def test_second_attempt_fails_even_without_a_token(self, client, manager):
        response = client.post(
            "/api/auth/bootstrap-manager",
            json={"name": "Sneaky", "phone": "+254700000002", "email": "sneaky@routify.test", "password": "Pass12345"},
        )
        assert response.status_code == 403

    def test_missing_fields_returns_400(self, client):
        response = client.post("/api/auth/bootstrap-manager", json={"name": "Incomplete"})
        assert response.status_code == 400

    def test_short_password_returns_400(self, client):
        response = client.post(
            "/api/auth/bootstrap-manager",
            json={"name": "Root", "phone": "+254700000001", "email": "root@routify.test", "password": "short"},
        )
        assert response.status_code == 400

class TestLoginRoute:
    def test_manager_login_succeeds(self, client, manager):
        response = client.post("/api/auth/login", json={"identifier": manager.email, "password": "ManagerPass123"})
        assert response.status_code == 200
        assert "access_token" in response.get_json()

    def test_driver_login_succeeds_with_phone(self, client, driver):
        response = client.post("/api/auth/login", json={"identifier": driver.phone, "password": "DriverPass123"})
        assert response.status_code == 200

    def test_wrong_password_returns_401(self, client, manager):
        response = client.post("/api/auth/login", json={"identifier": manager.email, "password": "wrong"})
        assert response.status_code == 401

    def test_unknown_identifier_returns_401_not_404(self, client):
        response = client.post("/api/auth/login", json={"identifier": "nobody@nowhere.test", "password": "x"})
        # Never leak whether an identifier exists via a different status code.
        assert response.status_code == 401

    def test_response_never_includes_password_hash(self, client, manager):
        response = client.post("/api/auth/login", json={"identifier": manager.email, "password": "ManagerPass123"})
        assert "password_hash" not in response.get_json()["user"]


class TestOnboardDriverRoute:
    def test_manager_can_onboard_driver(self, client, manager, auth_headers):
        response = client.post(
            "/api/auth/onboard-driver",
            json={"name": "Sam Driver", "phone": "+254711111111"},
            headers=auth_headers(manager),
        )
        assert response.status_code == 201
        body = response.get_json()
        assert body["driver_status"] == "pending_documents"
        assert body["must_change_password"] is True

    def test_requires_authentication(self, client):
        response = client.post("/api/auth/onboard-driver", json={"name": "Sam Driver", "phone": "+254711111111"})
        assert response.status_code == 401

    def test_driver_cannot_onboard_another_driver(self, client, driver, auth_headers):
        response = client.post(
            "/api/auth/onboard-driver",
            json={"name": "New Driver", "phone": "+254711111112"},
            headers=auth_headers(driver),
        )
        assert response.status_code == 403

    def test_duplicate_phone_returns_409(self, client, manager, driver, auth_headers):
        response = client.post(
            "/api/auth/onboard-driver",
            json={"name": "Dupe", "phone": driver.phone},
            headers=auth_headers(manager),
        )
        assert response.status_code == 409

    def test_invalid_phone_returns_400(self, client, manager, auth_headers):
        response = client.post(
            "/api/auth/onboard-driver",
            json={"name": "Bad Phone", "phone": "not-a-phone"},
            headers=auth_headers(manager),
        )
        assert response.status_code == 400

class TestPasswordChangeGate:
    def test_blocks_gated_route_until_password_changed(self, client, make_user, auth_headers):
        manager_needing_change = make_user(role="manager", must_change_password=True)
        response = client.post(
            "/api/auth/onboard-driver",
            json={"name": "Sam Driver", "phone": "+254711111111"},
            headers=auth_headers(manager_needing_change),
        )
        print("STATUS:", response.status_code)
        print("BODY:", response.get_json())
        assert response.status_code == 403

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