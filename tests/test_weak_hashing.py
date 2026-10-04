from pwdemo.weak_hashing import md5_hash, sha256_hash, HASH_FUNCTIONS


def test_md5_is_deterministic():
    assert md5_hash("hello") == md5_hash("hello")


def test_md5_different_inputs_different_outputs():
    assert md5_hash("hello") != md5_hash("world")


def test_md5_known_value():
    # Well-known reference value for md5("password")
    assert md5_hash("password") == "5f4dcc3b5aa765d61d8327deb882cf99"


def test_md5_output_is_hex_32_chars():
    h = md5_hash("anything")
    assert len(h) == 32
    assert all(c in "0123456789abcdef" for c in h)


def test_sha256_is_deterministic():
    assert sha256_hash("hello") == sha256_hash("hello")


def test_sha256_output_is_hex_64_chars():
    h = sha256_hash("anything")
    assert len(h) == 64


def test_sha256_known_value():
    assert sha256_hash("password") == (
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
    )


def test_no_salt_same_password_same_hash_every_time():
    """The core property that makes these weak: identical input always
    produces identical output, with nothing random involved."""
    hashes = {md5_hash("repeat-me") for _ in range(5)}
    assert len(hashes) == 1


def test_hash_functions_registry():
    assert HASH_FUNCTIONS["md5"] is md5_hash
    assert HASH_FUNCTIONS["sha256"] is sha256_hash
