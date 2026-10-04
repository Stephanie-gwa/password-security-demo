from pwdemo.comparison import run_full_comparison
from pwdemo.synthetic_data import TARGET_SCENARIOS


def test_full_comparison_runs_and_returns_results():
    report = run_full_comparison()
    assert len(report.results) > 0


def test_full_comparison_finishes_quickly():
    """The whole premise of this project: every search stays small
    enough that the full demo runs in well under a minute."""
    report = run_full_comparison()
    assert report.total_seconds < 30


def test_dictionary_hit_scenario_cracked_by_every_precomputation_method():
    report = run_full_comparison()
    rows = [r for r in report.results if r["scenario"] == "dictionary_hit"]
    methods = {r["method"] for r in rows}
    assert {"dictionary_unsalted", "lookup_table", "rainbow_table"} <= methods
    for r in rows:
        assert r["found"] is True
        assert r["correct"] is True
        assert r["password"] == TARGET_SCENARIOS["dictionary_hit"]["password"]


def test_bruteforce_only_scenario_fails_dictionary_succeeds_bruteforce():
    report = run_full_comparison()
    rows = {r["method"]: r for r in report.results if r["scenario"] == "bruteforce_only"}
    assert rows["dictionary_unsalted"]["found"] is False
    assert rows["bruteforce_unsalted"]["found"] is True
    assert rows["bruteforce_unsalted"]["password"] == TARGET_SCENARIOS["bruteforce_only"]["password"]


def test_outside_bounds_scenario_fails_every_method():
    report = run_full_comparison()
    rows = [r for r in report.results if r["scenario"] == "outside_bounds"]
    assert len(rows) > 0
    assert all(r["found"] is False for r in rows)


def test_salted_comparison_lookup_table_fails():
    """The core teaching point: a table precomputed over unsalted hashes
    cannot match a salted hash at all, regardless of whether the
    password is 'in' the table's wordlist."""
    report = run_full_comparison()
    row = next(r for r in report.results
               if r["scenario"] == "salted_comparison" and r["method"] == "lookup_table")
    assert row["found"] is False


def test_salted_comparison_dictionary_attack_still_succeeds_but_slower():
    report = run_full_comparison()
    salted = next(r for r in report.results
                  if r["scenario"] == "salted_comparison" and r["method"] == "dictionary_salted")
    unsalted = next(r for r in report.results
                    if r["scenario"] == "dictionary_hit" and r["method"] == "dictionary_unsalted")
    assert salted["found"] is True
    assert salted["password"] == TARGET_SCENARIOS["salted_comparison"]["password"]
    # same underlying password/position, but the salted version must be
    # dramatically slower per guess
    assert salted["elapsed_seconds"] > unsalted["elapsed_seconds"] * 100


def test_lookup_table_stats_present():
    report = run_full_comparison()
    assert report.lookup_table_stats["entries"] > 0


def test_rainbow_table_stats_present():
    report = run_full_comparison()
    assert report.rainbow_table_stats["stored_chains"] > 0
    assert report.rainbow_table_stats["theoretical_coverage"] > report.rainbow_table_stats["stored_chains"]


def test_report_to_dict_json_serializable():
    import json
    report = run_full_comparison()
    text = json.dumps(report.to_dict())
    assert "dictionary_hit" in text
