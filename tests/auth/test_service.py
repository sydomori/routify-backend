import pytest

from app.auth.exceptions import(
    DuplicateUserError,
    InvalidDriverStatusError,
    NotADriverError,
    UserNotFoundError
)

from app.auth.utils import verify_password

from app.auth import service

@pytest.fixture(autouse=True)
def _app_context(app):
    yield

class TestOnboardDriver:
    def test_creates_driver_with_correct_defaults(self):
        driver = service.onboard_driver(name="Sam Driver", phone="+254711111111")

        assert driver.role == "driver"
        assert driver.driver_status == "pending_documents"
        assert driver.must_change_password is True
        assert driver.is_active is True
        assert driver.phone == "+254711111111"

    def test_password_hash_is_never_the_temp_password_in_plaintext(self):
        driver = service.onboard_driver(name="Sam Driver", phone="+254711111111")
        assert driver.password_hash != ""
        # We can't recover the temp password from the hash (that's the point),
        # but we can confirm it isn't stored as plaintext under any obvious key.
        assert "Sam Driver" not in driver.password_hash

    def test_duplicate_phone_raises(self):
        service.onboard_driver(name="First", phone="+254711111111")
        with pytest.raises(DuplicateUserError):
            service.onboard_driver(name="Second", phone="+254711111111")

    def test_invalid_phone_raises_value_error(self):
        with pytest.raises(ValueError):
            service.onboard_driver(name="Bad Phone", phone="not-a-phone")

    def test_missing_communications_module_does_not_prevent_creation(self):
        # communications/ doesn't exist in this codebase yet — onboarding must still
        # succeed (soft dependency), not raise ImportError up to the caller.
        driver = service.onboard_driver(name="Sam Driver", phone="+254711111111")
        assert driver.id is not None

class TestAuthenticatedUser:
    def test_correct_credentials_returns_user(self, manager):
        result = service.authenticate_user(manager.email, "ManagerPass123")
        assert result is not None
        assert result.id == manager.id

    def test_wrong_password_returns_none(self, manager):
        assert service.authenticate_user(manager.email, "WrongPassword") is None

    def test_unknown_identifier_returns_none(self):
        assert service.authenticate_user("nobody@nowhere.test", "whatever") is None

    def test_deactivated_user_returns_none(self, driver):
        driver.is_active = False
        from app.extensions import db
        db.session.commit()
        assert service.authenticate_user(driver.phone, "DriverPass123") is None

    @pytest.mark.parametrize("identifier,password", [("", "x"), ("x", ""), ("", "")])
    def test_empty_credentials_return_none(self, identifier, password):
        assert service.authenticate_user(identifier, password) is None

    def test_driver_can_authenticate_by_phone(self, driver):
        result = service.authenticate_user(driver.phone, "DriverPass123")
        assert result is not None

    def test_manager_can_authenticate_by_email(self, manager):
        result = service.authenticate_user(manager.email, "ManagerPass123")
        assert result is not None


class TestChangePassword:
    def test_sets_must_change_password_false(self, driver):
        driver.must_change_password = True
        from app.extensions import db
        db.session.commit()

        service.change_password(driver.id, "BrandNewPassword1")

        assert driver.must_change_password is False
        assert verify_password("BrandNewPassword1", driver.password_hash) is True

    def test_old_password_no_longer_works(self, driver):
        service.change_password(driver.id, "BrandNewPassword1")
        assert service.authenticate_user(driver.phone, "DriverPass123") is None

    def test_unknown_user_id_raises(self):
        with pytest.raises(UserNotFoundError):
            service.change_password(99999, "whatever")

class TestDriverStatusGuards:
    """These two functions are called directly by trucks/trips/documents modules —
    their exact behavior is a cross-module contract, not just an implementation detail."""

    def test_get_driver_status_returns_current_status(self, driver):
        assert service.get_driver_status(driver.id) == "pending_documents"

    def test_get_driver_status_on_manager_raises_not_a_driver(self, manager):
        with pytest.raises(NotADriverError):
            service.get_driver_status(manager.id)

    def test_get_driver_status_unknown_id_raises(self):
        with pytest.raises(UserNotFoundError):
            service.get_driver_status(99999)

    def test_set_driver_status_updates_value(self, driver):
        service.set_driver_status(driver.id, "verified")
        assert service.get_driver_status(driver.id) == "verified"

    @pytest.mark.parametrize("status", ["pending_documents", "pending_review", "verified", "rejected"])
    def test_set_driver_status_accepts_all_valid_values(self, driver, status):
        service.set_driver_status(driver.id, status)
        assert service.get_driver_status(driver.id) == status

    def test_set_driver_status_rejects_invalid_value(self, driver):
        with pytest.raises(InvalidDriverStatusError):
            service.set_driver_status(driver.id, "not_a_real_status")

    def test_set_driver_status_on_manager_raises_not_a_driver(self, manager):
        with pytest.raises(NotADriverError):
            service.set_driver_status(manager.id, "verified")

class TestDeactivateDriver:
    def test_sets_is_active_false(self, driver):
        service.deactivate_driver(driver.id)
        assert driver.is_active is False

    def test_deactivated_driver_cannot_authenticate(self, driver):
        service.deactivate_driver(driver.id)
        assert service.authenticate_user(driver.phone, "DriverPass123") is None

    def test_on_manager_raises_not_a_driver(self, manager):
        with pytest.raises(NotADriverError):
            service.deactivate_driver(manager.id)

    def test_unknown_id_raises(self):
        with pytest.raises(UserNotFoundError):
            service.deactivate_driver(99999)

class TestGetUserById:
    def test_returns_matching_user(self, driver):
        assert service.get_user_by_id(driver.id).id == driver.id

    def test_unknown_id_raises(self):
        with pytest.raises(UserNotFoundError):
            service.get_user_by_id(99999)

class TestBootstrapFirstManager:
    def test_succeeds_when_no_managers_exist(self):
        manager = service.bootstrap_first_manager(
            name="Root", phone="+254700000001", email="root@routify.test", password="RootPass123"
        )
        assert manager.role == "manager"
        assert manager.must_change_password is False
        assert manager.is_active is True

    def test_fails_once_a_manager_already_exists(self, manager):
        with pytest.raises(PermissionError):
            service.bootstrap_first_manager(
                name="Second", phone="+254700000002", email="second@routify.test", password="Pass12345"
            )

    def test_duplicate_email_raises(self, manager):
        # manager fixture already exists, so this should hit the "manager already exists"
        # PermissionError before it ever gets to check email uniqueness — confirms ordering.
        with pytest.raises(PermissionError):
            service.bootstrap_first_manager(
                name="Dupe", phone="+254700000003", email=manager.email, password="Pass12345"
            )

    def test_invalid_phone_raises_value_error(self):
        with pytest.raises(ValueError):
            service.bootstrap_first_manager(
                name="Bad", phone="not-a-phone", email="bad@routify.test", password="Pass12345"
            )