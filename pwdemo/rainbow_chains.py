"""
rainbow_chains.py — a real, working (if tiny) rainbow table.

The idea a plain lookup table (lookup_table.py) can't capture: instead
of storing every (hash, password) pair, a rainbow table stores CHAINS —
alternating hash and "reduction" steps starting from some password —
and keeps only each chain's start and end password. Cracking a target
hash means walking a *new*, short chain from the target forward until
it reaches a stored endpoint, then regenerating that whole chain from
its stored start to find exactly where the target hash actually
occurred. That's a real re-computation at lookup time, traded against
storing far fewer entries than a full lookup table would need to cover
the same number of passwords.

Two things this implementation is careful to get right, because they're
easy to gloss over:

  1. POSITION-DEPENDENT REDUCTION. The reduction function used at chain
     position i must differ per position (R_0, R_1, ..., R_{k-1}), or
     every chain that ever collides at any point would immediately
     merge and stay merged, collapsing the table's coverage. This is
     literally where the "rainbow" in "rainbow table" comes from: each
     position/column uses a different-colored reduction function.
  2. FALSE ALARMS. A candidate chain can reach a stored endpoint even
     when the target hash was never actually part of that chain (two
     different chains can coincidentally end at the same password).
     Real rainbow table implementations have to detect and skip these
     by regenerating the full chain and checking — this implementation
     does exactly that, rather than pretending it can't happen.
"""
from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Callable

from .dictionary_attack import AttackResult


def reduce_hash(hash_hex: str, position: int, charset: str, length: int) -> str:
    """Map a hash to a plausible password candidate, mixing in the chain
    position so different positions produce different mappings even for
    the same input hash."""
    n = len(charset)
    space = n ** length
    h_int = int(hash_hex, 16)
    # 2654435761 is Knuth's multiplicative-hashing constant (2^32 / golden
    # ratio, rounded to the nearest prime) — used here only to spread the
    # position offset across the index space, not for any cryptographic
    # purpose.
    idx = (h_int + position * 2654435761) % space
    chars = []
    for _ in range(length):
        idx, rem = divmod(idx, n)
        chars.append(charset[rem])
    return "".join(reversed(chars))


def generate_chain(start_password: str, chain_length: int, hash_fn: Callable[[str], str],
                    charset: str, length: int) -> str:
    """Walk hash -> reduce, chain_length times, and return the endpoint."""
    current = start_password
    for position in range(chain_length):
        h = hash_fn(current)
        current = reduce_hash(h, position, charset, length)
    return current


@dataclass
class RainbowTable:
    chains: dict            # end_password -> start_password (ONLY the endpoints are stored)
    chain_length: int
    charset: str
    length: int
    hash_fn: Callable
    hash_fn_name: str
    build_seconds: float
    starts_considered: int   # how many start passwords were used to build the table

    @property
    def stored_chains(self) -> int:
        return len(self.chains)

    @property
    def theoretical_coverage(self) -> int:
        """Roughly how many distinct passwords the table's chains pass
        through, IF there were no merges. Real coverage is usually a bit
        lower — see README for why."""
        return self.stored_chains * self.chain_length

    def crack(self, target_hash: str) -> AttackResult:
        start = time.perf_counter()
        operations = 0

        for j in range(self.chain_length - 1, -1, -1):
            candidate = reduce_hash(target_hash, j, self.charset, self.length)
            operations += 1
            for pos in range(j + 1, self.chain_length):
                candidate = reduce_hash(self.hash_fn(candidate), pos, self.charset, self.length)
                operations += 1

            start_password = self.chains.get(candidate)
            if start_password is None:
                continue  # this position's guess doesn't land on any stored chain endpoint

            # Candidate endpoint matched — regenerate the WHOLE chain from
            # its recorded start to find the actual plaintext. This also
            # naturally detects and skips false alarms.
            current = start_password
            for pos in range(self.chain_length):
                h = self.hash_fn(current)
                operations += 1
                if h == target_hash:
                    return AttackResult(
                        method="rainbow_table", found=True, password=current,
                        attempts_tried=operations, elapsed_seconds=time.perf_counter() - start,
                        keyspace_size=self.stored_chains,
                        notes=f"recovered via chain regeneration ({self.stored_chains} stored "
                              f"chains x up to {self.chain_length} steps each)",
                    )
                current = reduce_hash(h, pos, self.charset, self.length)
            # else: false alarm — this endpoint matched by coincidence, not
            # because the target hash was really in this chain. Keep
            # trying smaller j.

        return AttackResult(
            method="rainbow_table", found=False, password=None, attempts_tried=operations,
            elapsed_seconds=time.perf_counter() - start, keyspace_size=self.stored_chains,
            notes="target hash not reachable from any stored chain",
        )


def build_rainbow_table(
    start_passwords: list, chain_length: int, hash_fn: Callable[[str], str],
    charset: str, length: int, hash_fn_name: str = "unknown",
) -> RainbowTable:
    start_time = time.perf_counter()
    chains = {}
    for start_pw in start_passwords:
        end_pw = generate_chain(start_pw, chain_length, hash_fn, charset, length)
        chains.setdefault(end_pw, start_pw)  # first chain to reach an endpoint keeps it (a merge)
    return RainbowTable(
        chains=chains, chain_length=chain_length, charset=charset, length=length,
        hash_fn=hash_fn, hash_fn_name=hash_fn_name,
        build_seconds=time.perf_counter() - start_time, starts_considered=len(start_passwords),
    )
