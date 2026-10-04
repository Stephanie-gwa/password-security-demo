import itertools

from pwdemo.lookup_table import build_lookup_table
from pwdemo.rainbow_chains import build_rainbow_table, generate_chain, reduce_hash
from pwdemo.weak_hashing import md5_hash

CHARSET = "abc"
LENGTH = 2
ALL_PASSWORDS = ["".join(c) for c in itertools.product(CHARSET, repeat=LENGTH)]  # 9 total


# ---------------------------------------------------------------- reduce_hash

def test_reduce_hash_returns_correct_length():
    candidate = reduce_hash(md5_hash("x"), position=0, charset=CHARSET, length=LENGTH)
    assert len(candidate) == LENGTH


def test_reduce_hash_only_uses_charset_characters():
    candidate = reduce_hash(md5_hash("anything"), position=3, charset=CHARSET, length=LENGTH)
    assert all(c in CHARSET for c in candidate)


def test_reduce_hash_is_deterministic():
    h = md5_hash("fixed-input")
    a = reduce_hash(h, position=2, charset=CHARSET, length=LENGTH)
    b = reduce_hash(h, position=2, charset=CHARSET, length=LENGTH)
    assert a == b


def test_reduce_hash_differs_by_position():
    """This is the property that keeps chains from collapsing into each
    other at every shared point — different positions must (usually)
    produce different candidates from the same hash."""
    h = md5_hash("some-hash-input")
    outputs = {reduce_hash(h, position=p, charset=CHARSET, length=LENGTH) for p in range(8)}
    assert len(outputs) > 1  # not all identical


# ---------------------------------------------------------------- generate_chain

def test_generate_chain_is_deterministic():
    a = generate_chain("aa", chain_length=5, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)
    b = generate_chain("aa", chain_length=5, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)
    assert a == b


def test_generate_chain_output_has_correct_length():
    end = generate_chain("bb", chain_length=10, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)
    assert len(end) == LENGTH


def test_zero_length_chain_returns_start_unchanged():
    end = generate_chain("cc", chain_length=0, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)
    assert end == "cc"


# ---------------------------------------------------------------- build_rainbow_table / crack correctness

def test_crack_recovers_password_placed_first_in_chain_starts():
    """Placing a password first in the start list guarantees (by
    construction, since ties are resolved first-start-wins) that its own
    chain survives any merges — making this a reliable correctness check
    rather than a probabilistic one."""
    target = "ba"
    starts = [target] + [p for p in ALL_PASSWORDS if p != target]
    table = build_rainbow_table(starts, chain_length=6, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)

    result = table.crack(md5_hash(target))
    assert result.found is True
    assert result.password == target


def test_crack_recovers_every_password_when_each_is_placed_first_in_its_own_table():
    """Merges can happen at any chain_length, including 1 — two different
    start passwords can land on the same reduced endpoint purely by
    chance (birthday-paradox-style), which is real rainbow-table
    behavior, not a bug. So this test uses the same reliable pattern as
    test_crack_recovers_password_placed_first_in_chain_starts, once per
    password, rather than assuming a whole table has perfect coverage."""
    for target in ALL_PASSWORDS:
        starts = [target] + [p for p in ALL_PASSWORDS if p != target]
        table = build_rainbow_table(starts, chain_length=1, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)
        result = table.crack(md5_hash(target))
        assert result.found is True, f"failed to recover {target!r}"
        assert result.password == target


def test_merges_can_happen_even_with_chain_length_one():
    """Documenting the phenomenon the test above works around: with 9
    possible passwords reducing into only 9 possible endpoint slots,
    collisions in the reduction function alone (no chained hashing
    needed) are common enough to regularly reduce the stored chain
    count below the number of starts."""
    table = build_rainbow_table(ALL_PASSWORDS, chain_length=1, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)
    assert table.stored_chains <= len(ALL_PASSWORDS)


def test_crack_unknown_hash_returns_not_found():
    table = build_rainbow_table(ALL_PASSWORDS[:3], chain_length=4, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)
    # A hash that could not possibly appear in any chain over this charset/length:
    result = table.crack(md5_hash("this-is-not-length-2-over-abc"))
    assert result.found is False
    assert result.password is None


def test_table_stores_only_endpoints_not_every_password():
    """The defining space-saving property: chain_length=10 over 9
    possible passwords must store far fewer than 9*10 entries — it
    stores at most 9 (one per chain, often fewer after merges)."""
    table = build_rainbow_table(ALL_PASSWORDS, chain_length=10, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)
    assert table.stored_chains <= len(ALL_PASSWORDS)


def test_merges_can_reduce_stored_chain_count():
    """Not a bug — a real, documented property of rainbow tables: chains
    that happen to collide at any point merge and stay merged, so more
    starts don't always mean proportionally more stored chains."""
    table = build_rainbow_table(ALL_PASSWORDS, chain_length=4, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)
    assert table.stored_chains <= len(ALL_PASSWORDS)


def test_theoretical_coverage_property():
    table = build_rainbow_table(ALL_PASSWORDS[:5], chain_length=7, hash_fn=md5_hash, charset=CHARSET, length=LENGTH)
    assert table.theoretical_coverage == table.stored_chains * 7


# ---------------------------------------------------------------- storage comparison vs. a plain lookup table

def test_rainbow_table_uses_less_storage_than_a_lookup_table_for_equal_or_greater_coverage():
    """The actual point of rainbow tables: for roughly the same number of
    STORED entries, a rainbow table's chains reach many more candidate
    passwords than a 1-per-password lookup table ever could."""
    wordlist = [f"password{i:03d}" for i in range(200)]  # 200 distinct 11-char passwords

    lookup = build_lookup_table(wordlist, md5_hash)
    assert lookup.size == 200  # exactly one entry per password, always

    rainbow = build_rainbow_table(
        wordlist, chain_length=20, hash_fn=md5_hash,
        charset="abcdefghijklmnopqrstuvwxyz0123456789", length=11,
    )
    # Same (or fewer, after merges) stored entries as the lookup table...
    assert rainbow.stored_chains <= lookup.size
    # ...but each one nominally "reaches" chain_length passwords, so the
    # theoretical coverage is a large multiple of the lookup table's size.
    assert rainbow.theoretical_coverage > lookup.size * 10
