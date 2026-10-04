"""
weak_hashing.py — fast, unsalted hashes. This is deliberately how NOT to
store a password. It exists only so the demo has something realistic to
crack: no salt (so the same password always produces the same hash, and
a hash can be precomputed once and reused against any target), and a
fast general-purpose hash function (so an attacker can test millions of
guesses per second).
"""
from __future__ import annotations
import hashlib


def md5_hash(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def sha256_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


HASH_FUNCTIONS = {
    "md5": md5_hash,
    "sha256": sha256_hash,
}
