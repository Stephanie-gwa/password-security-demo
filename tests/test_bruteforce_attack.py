import pytest

from pwdemo.bruteforce_attack import (
    brute_force_unsalted, keyspace_size, validate_keyspace,
    KeyspaceTooLargeError, SAFETY_MAX_KEYSPACE,
)
from pwdemo.weak_hashing import md5_hash


def test_keyspace_size_single_length():
    # charset of 2, length 1 -> 2 combinations
    assert keyspace_size("ab", 1) == 2


def test_keyspace_size_multiple_lengths():
    # charset of 2: length 1 (2) + length 2 (4) = 6
    assert keyspace_size("ab", 2) == 6


def test_keyspace_size_matches_known_value():
    # lowercase+digits (36 chars), length <= 4
    size = keyspace_size("abcdefghijklmnopqrstuvwxyz0123456789", 4)
    assert size == 36 + 36**2 + 36**3 + 36**4


def test_validate_keyspace_within_bound_returns_size():
    assert validate_keyspace("ab", 2) == 6


def test_validate_keyspace_rejects_empty_charset():
    with pytest.raises(ValueError):
        validate_keyspace("", 3)


def test_validate_keyspace_rejects_zero_length():
    with pytest.raises(ValueError):
        validate_keyspace("abc", 0)


def test_validate_keyspace_enforces_safety_cap():
    """The hard guarantee: no combination of parameters can slip past
    the safety cap, regardless of what a caller asks for."""
    huge_charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    with pytest.raises(KeyspaceTooLargeError):
        validate_keyspace(huge_charset, 8)


def test_safety_cap_is_a_real_bound():
    assert SAFETY_MAX_KEYSPACE < 10_000_000  # sanity: it's actually small


# ---------------------------------------------------------------- brute_force_unsalted

def test_finds_short_password():
    target = md5_hash("ab1")
    result = brute_force_unsalted(target, md5_hash, "abc123", max_length=3)
    assert result.found is True
    assert result.password == "ab1"


def test_finds_single_character_password():
    target = md5_hash("z")
    result = brute_force_unsalted(target, md5_hash, "xyz", max_length=2)
    assert result.found is True
    assert result.password == "z"


def test_does_not_find_password_outside_charset():
    target = md5_hash("ab1")  # contains a digit
    result = brute_force_unsalted(target, md5_hash, "abc", max_length=3)  # letters only
    assert result.found is False


def test_does_not_find_password_longer_than_max_length():
    target = md5_hash("abcd")
    result = brute_force_unsalted(target, md5_hash, "abcd", max_length=3)
    assert result.found is False


def test_tries_shorter_lengths_first():
    """A 1-character match should be found well before the search would
    ever reach longer candidates."""
    target = md5_hash("c")
    result = brute_force_unsalted(target, md5_hash, "abc", max_length=4)
    assert result.attempts_tried == 3  # a, b, c — found on the 3rd try


def test_refuses_to_run_an_oversized_search():
    huge_charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    with pytest.raises(KeyspaceTooLargeError):
        brute_force_unsalted(md5_hash("x"), md5_hash, huge_charset, max_length=8)


def test_keyspace_size_reported_in_result():
    result = brute_force_unsalted(md5_hash("a"), md5_hash, "abc", max_length=2)
    assert result.keyspace_size == keyspace_size("abc", 2)


def test_not_found_reports_full_keyspace_as_attempts():
    result = brute_force_unsalted(md5_hash("zzzz-not-in-space"), md5_hash, "ab", max_length=2)
    assert result.found is False
    assert result.attempts_tried == keyspace_size("ab", 2)
