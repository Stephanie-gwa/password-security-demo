"""
bruteforce_attack.py — try every possible string up to a small length,
over a small character set. Unlike a dictionary attack, this needs no
wordlist at all — it just needs enough time, which is exactly why
keyspace size matters so much: it grows exponentially with length.

SAFETY_MAX_KEYSPACE is a hard ceiling this module refuses to exceed,
regardless of what charset/max_length a caller requests — this is what
actually keeps the search "bounded" in code, not just by choosing small
defaults and hoping nobody changes them.
"""
from __future__ import annotations
import itertools
import time
from typing import Callable

from .dictionary_attack import AttackResult

SAFETY_MAX_KEYSPACE = 3_000_000


class KeyspaceTooLargeError(ValueError):
    pass


def keyspace_size(charset: str, max_length: int) -> int:
    n = len(charset)
    return sum(n ** length for length in range(1, max_length + 1))


def validate_keyspace(charset: str, max_length: int) -> int:
    """Returns the keyspace size, or raises if it exceeds the safety cap."""
    if max_length < 1:
        raise ValueError("max_length must be at least 1")
    if len(charset) == 0:
        raise ValueError("charset must not be empty")
    size = keyspace_size(charset, max_length)
    if size > SAFETY_MAX_KEYSPACE:
        raise KeyspaceTooLargeError(
            f"Requested keyspace ({size:,} combinations) exceeds this project's safety "
            f"cap of {SAFETY_MAX_KEYSPACE:,}. Use a smaller charset or max_length — this "
            f"cap exists specifically so the demo can never accidentally run an unbounded "
            f"search."
        )
    return size


def brute_force_unsalted(
    target_hash: str, hash_fn: Callable[[str], str], charset: str, max_length: int,
) -> AttackResult:
    total = validate_keyspace(charset, max_length)
    start = time.perf_counter()
    attempts = 0
    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            candidate = "".join(combo)
            if hash_fn(candidate) == target_hash:
                return AttackResult(
                    method="bruteforce_unsalted", found=True, password=candidate,
                    attempts_tried=attempts, elapsed_seconds=time.perf_counter() - start,
                    keyspace_size=total,
                )
    return AttackResult(
        method="bruteforce_unsalted", found=False, password=None, attempts_tried=attempts,
        elapsed_seconds=time.perf_counter() - start, keyspace_size=total,
        notes="password not found within the bounded keyspace",
    )
