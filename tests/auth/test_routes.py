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