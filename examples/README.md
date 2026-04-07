# DEBACL Examples

## Quickstart

1. Install: `uv sync`
2. Run demo: `bash examples/demo.sh`
3. View findings: `ls output/demo/`

## Mock Mode

All collectors support `--mock` to generate synthetic data without API credentials.
Run `python -m debacl.cli.main collect --all --mock` to populate the database.
