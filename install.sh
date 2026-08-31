#!/usr/bin/env bash
set -euo pipefail

# install.sh - create a Python virtual environment and install runtime dependencies.
# Run this from the project root:
#   ./install.sh

cd "$(dirname "$0")"

if [ ! -x "$(command -v python3)" ]; then
  echo "Error: python3 is required but not found."
  exit 1
fi

python3 -m venv venv
. venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt

if [ -f "./install-tools.sh" ]; then
  echo "Installing external tools..."
  bash ./install-tools.sh
else
  echo "Warning: install-tools.sh not found. Skipping external tool installation."
fi

echo "Environment setup complete. Activate with: source venv/bin/activate"
