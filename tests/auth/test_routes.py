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