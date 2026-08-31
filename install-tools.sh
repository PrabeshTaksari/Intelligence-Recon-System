#!/usr/bin/env bash
set -euo pipefail

# install-tools.sh - install external scanner and reconnaissance tools.
# Run this from the project root:
#   ./install-tools.sh

cd "$(dirname "$0")"

# get a useful go binary directory if Go is installed
GO_BIN=""
if command -v go >/dev/null 2>&1; then
  GO_BIN=$(go env GOBIN)
  if [ -z "$GO_BIN" ] || [ "$GO_BIN" = "/" ]; then
    GO_BIN=$(go env GOPATH)/bin
  fi
  export PATH="$GO_BIN:$PATH"
fi

install_go_tool() {
  local pkg="$1"
  echo "Installing $pkg..."
  if ! go install "$pkg@latest"; then
    echo "Warning: failed to install $pkg"
  fi
}

if command -v go >/dev/null 2>&1; then
  install_go_tool github.com/projectdiscovery/httpx/cmd/httpx
  install_go_tool github.com/projectdiscovery/nuclei/v2/cmd/nuclei
  install_go_tool github.com/projectdiscovery/naabu/v2/cmd/naabu
  install_go_tool github.com/projectdiscovery/dnsx/cmd/dnsx
  install_go_tool github.com/projectdiscovery/shuffledns/cmd/shuffledns
  install_go_tool github.com/projectdiscovery/katana/cmd/katana
  install_go_tool github.com/projectdiscovery/gau/v2/cmd/gau
  install_go_tool github.com/jaeles-project/gospider
  install_go_tool github.com/projectdiscovery/subfinder/v2/cmd/subfinder
  install_go_tool github.com/tomnomnom/assetfinder
  install_go_tool github.com/ffuf/ffuf
  if ! install_go_tool github.com/OWASP/Amass/v3/...; then
    echo "Warning: Amass installation failed. Please install Amass manually if needed."
  fi
else
  echo "Warning: Go is not installed. Skipping Go-based tool installation."
  echo "Install Go and re-run ./install-tools.sh to install httpx, nuclei, naabu, dnsx, shuffledns, katana, gau, gospider, subfinder, assetfinder, ffuf, and amass."
fi

if [ -f "venv/bin/activate" ]; then
  printf "Activating Python virtual environment...\n"
  # shellcheck disable=SC1091
  . "venv/bin/activate"
  pip install --upgrade pip
  pip install wfuzz sublist3r
else
  echo "Warning: Python virtual environment not found. Run ./install.sh first."
fi

if command -v gem >/dev/null 2>&1; then
  echo "Installing CeWL via gem..."
  gem install cewl
else
  echo "Warning: gem is not installed. Skipping CeWL installation."
fi

echo "External tool installation complete."
if [ -n "$GO_BIN" ]; then
  echo "Go binaries installed to: $GO_BIN"
  echo "Ensure $GO_BIN is in your PATH."
fi
