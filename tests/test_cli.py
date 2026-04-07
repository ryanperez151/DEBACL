"""
Tests for the Typer CLI commands.

@decision DEC-PKG-001
@title Typer CLI — cleaner than click for typed Python, auto-generates help
@status accepted
@rationale CliRunner from typer.testing invokes the CLI entirely in-process,
           capturing stdout/stderr without spawning a subprocess. The CLI
           commands that require database access receive a temporary file-based
           SQLite path via monkeypatching _get_engine so tests remain isolated
           and deterministic.
"""

import os

from typer.testing import CliRunner

from debacl.cli.main import app

runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_patched_engine(tmp_path):
    """Return an initialised SQLite engine pointing to a temp file."""
    from debacl.storage.database import get_engine, init_db

    db_path = str(tmp_path / "test.db")
    engine = get_engine(f"sqlite:///{db_path}")
    init_db(engine)
    return engine


# ---------------------------------------------------------------------------
# Help output
# ---------------------------------------------------------------------------


class TestHelp:
    def test_app_help(self):
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "debacl" in result.output.lower()

    def test_collect_help(self):
        result = runner.invoke(app, ["collect", "--help"])
        assert result.exit_code == 0
        assert "--source" in result.output or "source" in result.output.lower()

    def test_correlate_help(self):
        result = runner.invoke(app, ["correlate", "--help"])
        assert result.exit_code == 0

    def test_report_help(self):
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0

    def test_status_help(self):
        result = runner.invoke(app, ["status", "--help"])
        assert result.exit_code == 0

    def test_serve_help(self):
        result = runner.invoke(app, ["serve", "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# status command
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status_runs_without_error(self, tmp_path, monkeypatch):
        engine = make_patched_engine(tmp_path)

        import debacl.cli.main as cli_module

        monkeypatch.setattr(cli_module, "_get_engine", lambda: engine)
        result = runner.invoke(app, ["status"])
        assert result.exit_code == 0

    def test_status_prints_counts(self, tmp_path, monkeypatch):
        engine = make_patched_engine(tmp_path)

        import debacl.cli.main as cli_module

        monkeypatch.setattr(cli_module, "_get_engine", lambda: engine)
        result = runner.invoke(app, ["status"])
        assert "Telemetry" in result.output or "telemetry" in result.output.lower()
        assert "Findings" in result.output or "findings" in result.output.lower()

    def test_status_shows_severity_breakdown(self, tmp_path, monkeypatch):
        engine = make_patched_engine(tmp_path)

        import debacl.cli.main as cli_module

        monkeypatch.setattr(cli_module, "_get_engine", lambda: engine)
        result = runner.invoke(app, ["status"])
        assert "critical" in result.output or "high" in result.output


# ---------------------------------------------------------------------------
# correlate command
# ---------------------------------------------------------------------------


class TestCorrelate:
    def test_correlate_runs_without_error(self, tmp_path, monkeypatch):
        engine = make_patched_engine(tmp_path)

        import debacl.cli.main as cli_module

        monkeypatch.setattr(cli_module, "_get_engine", lambda: engine)
        result = runner.invoke(app, ["correlate"])
        assert result.exit_code == 0

    def test_correlate_empty_db_reports_no_findings(self, tmp_path, monkeypatch):
        engine = make_patched_engine(tmp_path)

        import debacl.cli.main as cli_module

        monkeypatch.setattr(cli_module, "_get_engine", lambda: engine)
        result = runner.invoke(app, ["correlate"])
        assert "No findings" in result.output

    def test_correlate_window_option(self, tmp_path, monkeypatch):
        engine = make_patched_engine(tmp_path)

        import debacl.cli.main as cli_module

        monkeypatch.setattr(cli_module, "_get_engine", lambda: engine)
        result = runner.invoke(app, ["correlate", "--window", "48"])
        assert result.exit_code == 0

    def test_correlate_no_save(self, tmp_path, monkeypatch):
        engine = make_patched_engine(tmp_path)

        import debacl.cli.main as cli_module

        monkeypatch.setattr(cli_module, "_get_engine", lambda: engine)
        result = runner.invoke(app, ["correlate", "--no-save"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# report command
# ---------------------------------------------------------------------------


class TestReport:
    def _invoke_report(self, tmp_path, monkeypatch, *args):
        engine = make_patched_engine(tmp_path)

        import debacl.cli.main as cli_module

        monkeypatch.setattr(cli_module, "_get_engine", lambda: engine)
        output_dir = str(tmp_path / "report_out")
        return runner.invoke(app, ["report", "--output", output_dir, *args]), output_dir

    def test_report_json_runs_without_error(self, tmp_path, monkeypatch):
        result, _ = self._invoke_report(tmp_path, monkeypatch, "--format", "json")
        assert result.exit_code == 0

    def test_report_json_creates_output_file(self, tmp_path, monkeypatch):
        result, output_dir = self._invoke_report(tmp_path, monkeypatch, "--format", "json")
        assert result.exit_code == 0
        files = os.listdir(output_dir)
        json_files = [f for f in files if f.endswith(".json")]
        assert len(json_files) == 1

    def test_report_csv_runs_without_error(self, tmp_path, monkeypatch):
        result, _ = self._invoke_report(tmp_path, monkeypatch, "--format", "csv")
        assert result.exit_code == 0

    def test_report_csv_creates_output_file(self, tmp_path, monkeypatch):
        result, output_dir = self._invoke_report(tmp_path, monkeypatch, "--format", "csv")
        assert result.exit_code == 0
        files = os.listdir(output_dir)
        csv_files = [f for f in files if f.endswith(".csv")]
        assert len(csv_files) == 1

    def test_report_jsonl_creates_output_file(self, tmp_path, monkeypatch):
        result, output_dir = self._invoke_report(tmp_path, monkeypatch, "--format", "jsonl")
        assert result.exit_code == 0
        files = os.listdir(output_dir)
        jsonl_files = [f for f in files if f.endswith(".jsonl")]
        assert len(jsonl_files) == 1

    def test_report_invalid_format_exits_nonzero(self, tmp_path, monkeypatch):
        result, _ = self._invoke_report(tmp_path, monkeypatch, "--format", "xml")
        assert result.exit_code != 0

    def test_report_prints_exported_path(self, tmp_path, monkeypatch):
        result, _ = self._invoke_report(tmp_path, monkeypatch, "--format", "json")
        assert "Exported" in result.output or ".json" in result.output


# ---------------------------------------------------------------------------
# collect command
# ---------------------------------------------------------------------------


class TestCollect:
    def test_collect_help_shows_source_option(self):
        result = runner.invoke(app, ["collect", "--help"])
        assert result.exit_code == 0
        assert "--source" in result.output

    def test_collect_without_source_exits_with_error(self, tmp_path, monkeypatch):
        """collect with no --source and no --all should fail."""
        engine = make_patched_engine(tmp_path)

        import debacl.cli.main as cli_module

        monkeypatch.setattr(cli_module, "_get_engine", lambda: engine)
        result = runner.invoke(app, ["collect"])
        # Collectors are not available (Phase 2 not merged) so exit code 1
        assert result.exit_code != 0
