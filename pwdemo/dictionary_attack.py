"""
dictionary_attack.py — try every word in a (small, synthetic) wordlist
against a target hash. This is the same technique against both an
unsalted weak hash and a salted modern hash — the only difference is
how expensive each guess is to compute. That's the point: dictionary
attacks work against BOTH; salting and iteration count don't make a
weak password safe, they just raise the cost per guess.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .modern_hashing import ModernHash, verify_password


@dataclass
class AttackResult:
    method: str
    found: bool
    password: Optional[str]
    attempts_tried: int
    elapsed_seconds: float
    keyspace_size: Optional[int] = None
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "method": self.method, "found": self.found, "password": self.password,
            "attempts_tried": self.attempts_tried, "elapsed_seconds": round(self.elapsed_seconds, 6),
            "keyspace_size": self.keyspace_size, "notes": self.notes,
        }


def dictionary_attack_unsalted(target_hash: str, hash_fn: Callable[[str], str], wordlist: list) -> AttackResult:
    """hash_fn: e.g. weak_hashing.md5_hash. Tries each word, stops at the first hit."""
    start = time.perf_counter()
    for i, word in enumerate(wordlist, start=1):
        if hash_fn(word) == target_hash:
            return AttackResult(
                method="dictionary_unsalted", found=True, password=word, attempts_tried=i,
                elapsed_seconds=time.perf_counter() - start, keyspace_size=len(wordlist),
            )
    return AttackResult(
        method="dictionary_unsalted", found=False, password=None, attempts_tried=len(wordlist),
        elapsed_seconds=time.perf_counter() - start, keyspace_size=len(wordlist),
        notes="password not present in the wordlist",
    )


def dictionary_attack_salted(stored: ModernHash, wordlist: list) -> AttackResult:
    """Same idea, but each guess must be run through the full salted KDF
    (using the target's own salt and iteration count) rather than a
    cheap unsalted hash — this is why it's so much slower per guess."""
    start = time.perf_counter()
    for i, word in enumerate(wordlist, start=1):
        if verify_password(word, stored):
            return AttackResult(
                method="dictionary_salted", found=True, password=word, attempts_tried=i,
                elapsed_seconds=time.perf_counter() - start, keyspace_size=len(wordlist),
                notes=f"{stored.iterations:,} PBKDF2 iterations per guess",
            )
    return AttackResult(
        method="dictionary_salted", found=False, password=None, attempts_tried=len(wordlist),
        elapsed_seconds=time.perf_counter() - start, keyspace_size=len(wordlist),
        notes="password not present in the wordlist",
    )
