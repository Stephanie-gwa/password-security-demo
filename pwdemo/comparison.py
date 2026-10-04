"""
comparison.py — runs every attack method against every relevant target
scenario and produces one flat list of results, so the README's claims
are directly reproducible by running this module.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field

from . import bruteforce_attack, dictionary_attack, lookup_table, rainbow_chains
from .modern_hashing import DEFAULT_ITERATIONS, hash_password
from .synthetic_data import BRUTEFORCE_CHARSET, BRUTEFORCE_MAX_LENGTH, SYNTHETIC_WORDLIST, TARGET_SCENARIOS
from .weak_hashing import md5_hash

RAINBOW_CHAIN_LENGTH = 60


@dataclass
class ComparisonReport:
    results: list = field(default_factory=list)   # list[dict] — see to_dict()
    lookup_table_stats: dict = field(default_factory=dict)
    rainbow_table_stats: dict = field(default_factory=dict)
    total_seconds: float = 0.0

    def to_dict(self) -> dict:
        return {
            "results": self.results,
            "lookup_table_stats": self.lookup_table_stats,
            "rainbow_table_stats": self.rainbow_table_stats,
            "total_seconds": round(self.total_seconds, 6),
        }


def run_full_comparison() -> ComparisonReport:
    overall_start = time.perf_counter()
    results = []

    # Precompute the two precomputation-attack structures once, up front —
    # this is the entire point of precomputation: pay the cost once, reuse
    # it against every unsalted target below.
    table = lookup_table.build_lookup_table(SYNTHETIC_WORDLIST, md5_hash, hash_fn_name="md5")

    # Guarantee the scenarios we specifically demonstrate are reachable in
    # the rainbow table by seeding their passwords as chain starts first
    # (see rainbow_chains.py / README for why chain coverage is otherwise
    # probabilistic, not exhaustive — this is a deliberate, documented
    # choice for a reliable demo, not a hidden shortcut).
    demo_targets = [TARGET_SCENARIOS["dictionary_hit"]["password"], TARGET_SCENARIOS["rainbow_demo"]["password"]]
    rainbow_starts = demo_targets + [w for w in SYNTHETIC_WORDLIST if w not in demo_targets]
    rtable = rainbow_chains.build_rainbow_table(
        rainbow_starts, chain_length=RAINBOW_CHAIN_LENGTH, hash_fn=md5_hash,
        charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", length=10,
        hash_fn_name="md5",
    )

    # ---------------------------------------------------------- unsalted weak hash

    for name in ("dictionary_hit", "rainbow_demo"):
        password = TARGET_SCENARIOS[name]["password"]
        target_hash = md5_hash(password)

        r = dictionary_attack.dictionary_attack_unsalted(target_hash, md5_hash, SYNTHETIC_WORDLIST)
        results.append(_row(name, "unsalted_md5", password, r))

        r = table.crack(target_hash)
        results.append(_row(name, "unsalted_md5", password, r))

        r = rtable.crack(target_hash)
        results.append(_row(name, "unsalted_md5", password, r))

    # brute force only makes sense for the short, non-dictionary password
    bf_password = TARGET_SCENARIOS["bruteforce_only"]["password"]
    bf_hash = md5_hash(bf_password)
    r = dictionary_attack.dictionary_attack_unsalted(bf_hash, md5_hash, SYNTHETIC_WORDLIST)
    results.append(_row("bruteforce_only", "unsalted_md5", bf_password, r))
    r = bruteforce_attack.brute_force_unsalted(bf_hash, md5_hash, BRUTEFORCE_CHARSET, BRUTEFORCE_MAX_LENGTH)
    results.append(_row("bruteforce_only", "unsalted_md5", bf_password, r))

    # a password outside every bound, for contrast
    outside_password = TARGET_SCENARIOS["outside_bounds"]["password"]
    outside_hash = md5_hash(outside_password)
    r = dictionary_attack.dictionary_attack_unsalted(outside_hash, md5_hash, SYNTHETIC_WORDLIST)
    results.append(_row("outside_bounds", "unsalted_md5", outside_password, r))
    r = table.crack(outside_hash)
    results.append(_row("outside_bounds", "unsalted_md5", outside_password, r))

    # ---------------------------------------------------------- modern salted hash

    salted_password = TARGET_SCENARIOS["salted_comparison"]["password"]
    stored = hash_password(salted_password, iterations=DEFAULT_ITERATIONS)

    # precomputed tables were built against UNSALTED md5 hashes — they have
    # no way to match a salted PBKDF2 digest at all; demonstrate the lookup
    # failing outright rather than just asserting it in prose.
    r = table.crack(stored.derived_hex)
    results.append(_row("salted_comparison", "salted_pbkdf2", salted_password, r))

    r = dictionary_attack.dictionary_attack_salted(stored, SYNTHETIC_WORDLIST)
    results.append(_row("salted_comparison", "salted_pbkdf2", salted_password, r))

    return ComparisonReport(
        results=results,
        lookup_table_stats={
            "entries": table.size, "build_seconds": round(table.build_seconds, 6),
            "hash_fn": table.hash_fn_name,
        },
        rainbow_table_stats={
            "stored_chains": rtable.stored_chains, "chain_length": rtable.chain_length,
            "starts_considered": rtable.starts_considered,
            "theoretical_coverage": rtable.theoretical_coverage,
            "build_seconds": round(rtable.build_seconds, 6),
        },
        total_seconds=time.perf_counter() - overall_start,
    )


def _row(scenario: str, hash_scheme: str, actual_password: str, result) -> dict:
    d = result.to_dict()
    d["scenario"] = scenario
    d["hash_scheme"] = hash_scheme
    d["actual_password"] = actual_password
    d["correct"] = (result.password == actual_password) if result.found else None
    return d
