"""
modern_hashing.py — modern salted password hashing, using an
established, standardized construction: PBKDF2-HMAC-SHA256
(hashlib.pbkdf2_hmac), as specified in RFC 8018 / NIST SP 800-132.

Two things make this resistant to the attacks in this project, in
different ways:

  1. SALT — a random value stored alongside the hash, mixed into the
     derivation. Two users with the same password get different hashes,
     and an attacker can't reuse one precomputed table (a lookup table
     OR a rainbow table) across different targets — a new table would
     be needed per salt, which defeats the entire point of precomputing
     once and reusing many times.
  2. ITERATION COUNT — the derivation deliberately runs the underlying
     hash tens of thousands of times, making each individual guess far
     more expensive to compute. This does NOT make dictionary or
     brute-force attacks impossible — a weak password is still weak —
     it makes each guess cost more, which is a real, measurable
     slowdown but not an absolute defense. See README.

DEFAULT_ITERATIONS here is deliberately lower than current OWASP
guidance (600,000+ for PBKDF2-HMAC-SHA256 as of 2023) purely so this
bounded demo finishes in a reasonable time; see README for the
production-recommended value and why the demo doesn't use it.

If the optional `bcrypt` package is installed, this module also exposes
a thin wrapper around it for a second, industry-standard comparison
point — but nothing else in this project requires it.
"""
from __future__ import annotations
import hashlib
import hmac
import os
from dataclasses import dataclass

DEFAULT_ITERATIONS = 50_000
SALT_BYTES = 16


@dataclass
class ModernHash:
    salt: bytes
    iterations: int
    derived: bytes
    algorithm: str = "pbkdf2_hmac_sha256"

    @property
    def salt_hex(self) -> str:
        return self.salt.hex()

    @property
    def derived_hex(self) -> str:
        return self.derived.hex()

    def to_dict(self) -> dict:
        return {
            "algorithm": self.algorithm, "salt_hex": self.salt_hex,
            "iterations": self.iterations, "derived_hex": self.derived_hex,
        }


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS, salt: bytes = None) -> ModernHash:
    salt = salt if salt is not None else os.urandom(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return ModernHash(salt=salt, iterations=iterations, derived=derived)


def verify_password(password: str, stored: ModernHash) -> bool:
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), stored.salt, stored.iterations)
    # constant-time comparison — a naive `==` here would leak timing
    # information about how many leading bytes matched.
    return hmac.compare_digest(candidate, stored.derived)


# ---------------------------------------------------------------- optional bcrypt comparison

try:
    import bcrypt as _bcrypt
    HAVE_BCRYPT = True
except ImportError:
    _bcrypt = None
    HAVE_BCRYPT = False


def bcrypt_hash(password: str, rounds: int = 12) -> str:
    if not HAVE_BCRYPT:
        raise RuntimeError("The optional 'bcrypt' package is not installed. "
                            "Install it with: pip install bcrypt")
    return _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt(rounds)).decode("ascii")


def bcrypt_verify(password: str, hashed: str) -> bool:
    if not HAVE_BCRYPT:
        raise RuntimeError("The optional 'bcrypt' package is not installed. "
                            "Install it with: pip install bcrypt")
    return _bcrypt.checkpw(password.encode("utf-8"), hashed.encode("ascii"))
