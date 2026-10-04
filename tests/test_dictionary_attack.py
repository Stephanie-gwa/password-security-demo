from pwdemo.dictionary_attack import dictionary_attack_unsalted, dictionary_attack_salted
from pwdemo.modern_hashing import hash_password
from pwdemo.weak_hashing import md5_hash

WORDLIST = ["apple", "banana", "correcthorse", "dragon2023", "elephant"]


def test_finds_password_in_wordlist():
    target = md5_hash("dragon2023")
    result = dictionary_attack_unsalted(target, md5_hash, WORDLIST)
    assert result.found is True
    assert result.password == "dragon2023"


def test_attempts_tried_matches_position():
    target = md5_hash("dragon2023")  # 4th word, index 3
    result = dictionary_attack_unsalted(target, md5_hash, WORDLIST)
    assert result.attempts_tried == 4  # 1-indexed position


def test_first_word_takes_one_attempt():
    target = md5_hash("apple")
    result = dictionary_attack_unsalted(target, md5_hash, WORDLIST)
    assert result.attempts_tried == 1


def test_password_not_in_wordlist():
    target = md5_hash("not-in-the-list-at-all")
    result = dictionary_attack_unsalted(target, md5_hash, WORDLIST)
    assert result.found is False
    assert result.password is None
    assert result.attempts_tried == len(WORDLIST)


def test_keyspace_size_reported():
    result = dictionary_attack_unsalted(md5_hash("apple"), md5_hash, WORDLIST)
    assert result.keyspace_size == len(WORDLIST)


def test_result_to_dict():
    result = dictionary_attack_unsalted(md5_hash("apple"), md5_hash, WORDLIST)
    d = result.to_dict()
    assert d["method"] == "dictionary_unsalted"
    assert d["found"] is True
    assert d["password"] == "apple"


# ---------------------------------------------------------------- salted variant

def test_salted_attack_finds_password():
    stored = hash_password("correcthorse", iterations=1000)
    result = dictionary_attack_salted(stored, WORDLIST)
    assert result.found is True
    assert result.password == "correcthorse"
    assert result.method == "dictionary_salted"


def test_salted_attack_fails_gracefully_when_not_in_wordlist():
    stored = hash_password("totally-different-password", iterations=1000)
    result = dictionary_attack_salted(stored, WORDLIST)
    assert result.found is False
    assert result.password is None


def test_salted_attack_notes_iteration_count():
    stored = hash_password("apple", iterations=12345)
    result = dictionary_attack_salted(stored, WORDLIST)
    assert "12,345" in result.notes or "12345" in result.notes


def test_salted_attack_is_slower_than_unsalted_per_guess():
    """The whole point: same wordlist, same target password, but the
    salted version has to do real KDF work for every guess."""
    stored = hash_password("elephant", iterations=50_000)
    salted_result = dictionary_attack_salted(stored, WORDLIST)

    unsalted_result = dictionary_attack_unsalted(md5_hash("elephant"), md5_hash, WORDLIST)

    assert salted_result.attempts_tried == unsalted_result.attempts_tried  # same position
    assert salted_result.elapsed_seconds > unsalted_result.elapsed_seconds  # but much slower
