import pytest

from pwdemo.modern_hashing import hash_password, verify_password, HAVE_BCRYPT


def test_verify_correct_password():
    stored = hash_password("correct horse battery staple", iterations=1000)
    assert verify_password("correct horse battery staple", stored) is True


def test_verify_wrong_password():
    stored = hash_password("correct horse battery staple", iterations=1000)
    assert verify_password("wrong password", stored) is False


def test_same_password_different_salt_different_hash():
    """This is the whole point of salting: two hashes of the identical
    password must not match each other."""
    a = hash_password("same-password", iterations=1000)
    b = hash_password("same-password", iterations=1000)
    assert a.salt != b.salt
    assert a.derived != b.derived


def test_explicit_salt_is_reproducible():
    salt = b"\x01" * 16
    a = hash_password("pw", iterations=1000, salt=salt)
    b = hash_password("pw", iterations=1000, salt=salt)
    assert a.derived == b.derived  # same salt + same password -> same output


def test_salt_is_random_by_default():
    salts = {hash_password("x", iterations=1000).salt for _ in range(10)}
    assert len(salts) == 10  # vanishingly unlikely to collide 10 times if truly random


def test_derived_key_length_matches_sha256():
    stored = hash_password("pw", iterations=1000)
    assert len(stored.derived) == 32  # SHA-256 produces a 32-byte digest


def test_to_dict_shape():
    stored = hash_password("pw", iterations=1000)
    d = stored.to_dict()
    assert d["algorithm"] == "pbkdf2_hmac_sha256"
    assert d["iterations"] == 1000
    assert len(d["salt_hex"]) == 32  # 16 bytes -> 32 hex chars
    assert len(d["derived_hex"]) == 64


def test_higher_iterations_take_longer():
    import time
    t0 = time.perf_counter()
    hash_password("pw", iterations=1000)
    fast = time.perf_counter() - t0

    t0 = time.perf_counter()
    hash_password("pw", iterations=100_000)
    slow = time.perf_counter() - t0

    assert slow > fast


# ---------------------------------------------------------------- optional bcrypt

@pytest.mark.skipif(not HAVE_BCRYPT, reason="bcrypt is an optional dependency and isn't installed")
def test_bcrypt_hash_and_verify():
    from pwdemo.modern_hashing import bcrypt_hash, bcrypt_verify
    hashed = bcrypt_hash("test-password", rounds=4)  # low rounds — just proving it works, not timing it
    assert bcrypt_verify("test-password", hashed) is True
    assert bcrypt_verify("wrong-password", hashed) is False


def test_bcrypt_raises_clear_error_when_not_installed():
    if HAVE_BCRYPT:
        pytest.skip("bcrypt is installed in this environment; nothing to test here")
    from pwdemo.modern_hashing import bcrypt_hash
    with pytest.raises(RuntimeError, match="bcrypt"):
        bcrypt_hash("pw")
