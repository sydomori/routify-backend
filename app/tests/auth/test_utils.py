import pytest
from app.auth.utils import (
    generate_temp_password,
    hash_password,
    normalize_phone,
    verify_password
)

class TestPasswordHashing:
    def test_hash_and_verify_round_trip(self):
        hashed = hash_password("CorrectHorse1")
        assert verify_password("CorrectHorse1", hashed) is True

    def test_verify_rejects_wrong_password(self):
        hashed = hash_password("CorrectHorse1")
        assert verify_password("WrongPassword", hashed) is False

    def test_hash_is_never_the_plaintext(self):
        hashed = hash_password("CorrectHorse1")
        assert hashed != "CorrectHorse1"

    def test_two_hashes_of_same_password_differ(self):
        # bcrypt salts each hash independently — this is what makes rainbow tables useless.
        assert hash_password("SamePassword1") != hash_password("SamePassword1")

    @pytest.mark.parametrize("bad_hash", ["", "not-a-bcrypt-hash", None])
    def test_verify_handles_malformed_hash_without_raising(self, bad_hash):
        assert verify_password("anything", bad_hash) is False

    def test_verify_handles_empty_plaintext(self):
        hashed = hash_password("CorrectHorse1")
        assert verify_password("", hashed) is False