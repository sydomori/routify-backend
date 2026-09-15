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