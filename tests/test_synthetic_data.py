from pwdemo.synthetic_data import (
    SYNTHETIC_WORDLIST, TARGET_SCENARIOS, BRUTEFORCE_CHARSET, BRUTEFORCE_MAX_LENGTH,
)


def test_wordlist_has_no_duplicates():
    assert len(SYNTHETIC_WORDLIST) == len(set(SYNTHETIC_WORDLIST))


def test_wordlist_is_nonempty_and_bounded():
    # Bounded: this is a demo, not a real breach corpus.
    assert 50 < len(SYNTHETIC_WORDLIST) < 5000


def test_dictionary_hit_password_is_in_wordlist():
    assert TARGET_SCENARIOS["dictionary_hit"]["password"] in SYNTHETIC_WORDLIST


def test_rainbow_demo_password_is_in_wordlist():
    assert TARGET_SCENARIOS["rainbow_demo"]["password"] in SYNTHETIC_WORDLIST


def test_dictionary_hit_and_rainbow_demo_same_length():
    """Required by the fixed-length rainbow table used in this demo."""
    a = TARGET_SCENARIOS["dictionary_hit"]["password"]
    b = TARGET_SCENARIOS["rainbow_demo"]["password"]
    assert len(a) == len(b)


def test_bruteforce_only_password_not_in_wordlist():
    assert TARGET_SCENARIOS["bruteforce_only"]["password"] not in SYNTHETIC_WORDLIST


def test_bruteforce_only_password_within_bruteforce_bounds():
    pw = TARGET_SCENARIOS["bruteforce_only"]["password"]
    assert len(pw) <= BRUTEFORCE_MAX_LENGTH
    assert all(c in BRUTEFORCE_CHARSET for c in pw)


def test_outside_bounds_password_not_in_wordlist_and_not_bruteforceable():
    pw = TARGET_SCENARIOS["outside_bounds"]["password"]
    assert pw not in SYNTHETIC_WORDLIST
    assert len(pw) > BRUTEFORCE_MAX_LENGTH or any(c not in BRUTEFORCE_CHARSET for c in pw)


def test_every_scenario_has_a_password_and_explanation():
    for name, info in TARGET_SCENARIOS.items():
        assert isinstance(info["password"], str) and info["password"]
        assert isinstance(info["explain"], str) and info["explain"]
