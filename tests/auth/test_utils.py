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

class TestTempPasswordHashing:
    def test_default_length_is_eight(self):
        assert len(generate_temp_password()) == 8

    def test_respects_custom_length(self):
        assert len(generate_temp_password(length=12)) == 12

    def test_excludes_visually_ambiguous_characters(self):
        ambiguous = set("0O1lI")
        # Generate a large sample rather than asserting on one draw — a single password
        # not containing '0' proves nothing about whether '0' is excluded.
        sample = "".join(generate_temp_password(length=64) for _ in range(20))
        assert not (set(sample) & ambiguous)

    def test_two_calls_produce_different_passwords(self):
        # Not a proof of randomness, but catches an accidentally-deterministic implementation.
        passwords = {generate_temp_password() for _ in range(20)}
        assert len(passwords) == 20

class TestPhoneNormalization:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("+254711111111", "+254711111111"),
            ("254711111111", "254711111111"),
            ("+254 711 111 111", "+254711111111"),
            ("+254-711-111-111", "+254711111111"),
        ],
    )
    def test_valid_formats_normalize_correctly(self, raw, expected):
        assert normalize_phone(raw) == expected

    @pytest.mark.parametrize(
        "invalid",
        ["not-a-phone", "12345", "", "abc123456789", "+0123456789"],
    )
    def test_invalid_formats_raise_value_error(self, invalid):
        with pytest.raises(ValueError):
            normalize_phone(invalid)