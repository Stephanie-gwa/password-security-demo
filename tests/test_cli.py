import json

from pwdemo import cli


def test_run_command_exits_zero(capsys):
    rc = cli.main(["run", "--quiet"])
    assert rc == 0


def test_run_command_prints_table(capsys):
    cli.main(["run", "--quiet"])
    out = capsys.readouterr().out
    assert "dictionary_hit" in out
    assert "Lookup table:" in out
    assert "Rainbow table:" in out


def test_run_command_writes_json_output(tmp_path, capsys):
    out_path = tmp_path / "results.json"
    rc = cli.main(["run", "--quiet", "--output", str(out_path)])
    assert rc == 0
    data = json.loads(out_path.read_text())
    assert "results" in data
    assert len(data["results"]) > 0


def test_list_scenarios_command(capsys):
    rc = cli.main(["list-scenarios"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dictionary_hit" in out
    assert "rainbow_demo" in out


def test_no_command_shows_help():
    import pytest
    with pytest.raises(SystemExit):
        cli.main([])


def test_format_table_contains_expected_columns():
    from pwdemo.comparison import run_full_comparison
    report = run_full_comparison()
    table_text = cli.format_table(report)
    assert "Scenario" in table_text
    assert "Method" in table_text
    assert "Found" in table_text
