from pwdemo.lookup_table import build_lookup_table
from pwdemo.weak_hashing import md5_hash

WORDLIST = ["apple", "banana", "cherry"]


def test_table_size_matches_wordlist():
    table = build_lookup_table(WORDLIST, md5_hash)
    assert table.size == len(WORDLIST)


def test_crack_finds_known_password():
    table = build_lookup_table(WORDLIST, md5_hash)
    result = table.crack(md5_hash("banana"))
    assert result.found is True
    assert result.password == "banana"


def test_crack_reports_single_attempt():
    """The whole point of a precomputed table: the lookup itself is O(1),
    unlike a live dictionary attack that might need many attempts."""
    table = build_lookup_table(WORDLIST, md5_hash)
    result = table.crack(md5_hash("cherry"))
    assert result.attempts_tried == 1


def test_crack_misses_unknown_hash():
    table = build_lookup_table(WORDLIST, md5_hash)
    result = table.crack(md5_hash("not-in-the-list"))
    assert result.found is False
    assert result.password is None


def test_build_time_recorded():
    table = build_lookup_table(WORDLIST, md5_hash)
    assert table.build_seconds >= 0


def test_lookup_is_much_faster_than_building():
    """Once built, a lookup should be extremely fast regardless of how
    long the original precomputation took — that's the entire tradeoff
    a lookup table makes."""
    import time
    large_wordlist = [f"word{i}" for i in range(5000)]
    table = build_lookup_table(large_wordlist, md5_hash)

    t0 = time.perf_counter()
    table.crack(md5_hash("word4999"))
    lookup_time = time.perf_counter() - t0

    assert lookup_time < table.build_seconds


def test_hash_fn_name_stored():
    table = build_lookup_table(WORDLIST, md5_hash, hash_fn_name="md5")
    assert table.hash_fn_name == "md5"


def test_duplicate_passwords_collapse_to_one_entry():
    table = build_lookup_table(["same", "same", "same"], md5_hash)
    assert table.size == 1
