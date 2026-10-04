"""
lookup_table.py — a SIMPLE precomputed lookup table: compute the hash of
every password in the wordlist once, store every (hash -> password)
pair, and look up a target hash directly in that table.

This is the plainest possible precomputation attack, and it's important
to be precise about what it is and isn't:

  - It IS the same core idea behind rainbow tables: trade attack-time
    computation for storage done once, ahead of time, then reused
    against many targets.
  - It is NOT a rainbow table. A simple lookup table stores one entry
    per password — its size equals the size of the wordlist. A real
    rainbow table (see rainbow_chains.py) stores only the two endpoints
    of a *chain* of many passwords, trading a cheap re-computation at
    lookup time for dramatically less storage. For this project's small
    synthetic wordlist the difference in storage isn't dramatic, but at
    real-world scale (billions of passwords) it's the entire reason
    rainbow tables exist instead of just using a bigger lookup table.

Either way, BOTH are defeated by a per-password salt (see
modern_hashing.py and README) — the attacker would need a fresh table
per salt, which erases the "compute once, reuse many times" advantage
that makes precomputation attacks worth doing in the first place.
"""
from __future__ import annotations
import time
from dataclasses import dataclass
from typing import Callable, Optional

from .dictionary_attack import AttackResult


@dataclass
class LookupTable:
    table: dict            # hash_hex -> password
    hash_fn_name: str
    build_seconds: float

    @property
    def size(self) -> int:
        return len(self.table)

    def crack(self, target_hash: str) -> AttackResult:
        start = time.perf_counter()
        password = self.table.get(target_hash)
        elapsed = time.perf_counter() - start
        return AttackResult(
            method="lookup_table", found=password is not None, password=password,
            attempts_tried=1, elapsed_seconds=elapsed, keyspace_size=self.size,
            notes="single dict lookup — the search cost was paid when the table was built"
                  if password else "hash not present in this table",
        )


def build_lookup_table(wordlist: list, hash_fn: Callable[[str], str], hash_fn_name: str = "unknown") -> LookupTable:
    start = time.perf_counter()
    table = {hash_fn(word): word for word in wordlist}
    return LookupTable(table=table, hash_fn_name=hash_fn_name, build_seconds=time.perf_counter() - start)
