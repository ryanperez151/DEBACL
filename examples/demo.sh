#!/usr/bin/env bash
# DEBACL End-to-End Demo
#
# Demonstrates the full DEBACL pipeline using the installed CLI.
# Requires: uv sync (or a virtualenv with debacl installed)
#
# Usage:
#   bash examples/demo.sh
set -e

echo "=== DEBACL Demo ==="
echo ""
echo "1. Checking status (empty database)..."
python -m debacl.cli.main status

echo ""
echo "2. Seeding demo data and running correlation..."
python -m debacl.cli.main correlate --window 24

echo ""
echo "3. Exporting findings as JSON..."
python -m debacl.cli.main report --format json --output output/demo

echo ""
echo "4. Exporting findings as CSV..."
python -m debacl.cli.main report --format csv --output output/demo

echo ""
echo "Done. Check output/demo/ for exported findings."
