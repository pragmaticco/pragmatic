#!/usr/bin/env bash
# The Stet demo, in one command:
#
#   examples/demo/run.sh            # add --open to open the auditor's report at the end
#
# It checks for the free developer tools it needs (Rust, Python 3.10 or
# later, OpenSSL 3) and says how to install any that are missing, builds
# Stet from this checkout, then tells the whole product story step by
# step. See README.md next to this file.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEMO="$ROOT/examples/demo"
VENV="${PRAGMATIC_DEMO_VENV:-$DEMO/.venv}"
LOG="$(mktemp -t pragmatic-demo-build.XXXXXX)"

python_ok() { "$1" -c 'import sys; sys.exit(sys.version_info < (3, 10))' >/dev/null 2>&1; }
# OpenSSL (not the LibreSSL macOS ships) whose ts command takes -partial_chain:
# the server and both verifiers check time-stamps with it.
openssl_ok() {
  local version usage
  version="$("$1" version 2>/dev/null)" || return 1
  usage="$("$1" ts -help 2>&1)" || true
  [[ "$version" == OpenSSL* && "$usage" == *-partial_chain* ]]
}

missing=()

if ! command -v cargo >/dev/null 2>&1; then
  missing+=("rust")
else
  # The workspace needs Rust 1.89 or later.
  rust_minor="$(rustc --version 2>/dev/null | sed -E 's/^rustc 1\.([0-9]+).*/\1/')"
  if [[ -n "$rust_minor" && "$rust_minor" =~ ^[0-9]+$ && "$rust_minor" -lt 89 ]]; then
    echo "Rust $(rustc --version | cut -d' ' -f2) is too old for Stet (1.89 or later)."
    echo "Update it with:  rustup update   (or, if Homebrew installed it: brew upgrade rust)"
    exit 1
  fi
fi

PYTHON=""
for candidate in python3.14 python3.13 python3.12 python3.11 python3.10 python3 \
  /opt/homebrew/bin/python3 /usr/local/bin/python3; do
  if command -v "$candidate" >/dev/null 2>&1 && python_ok "$(command -v "$candidate")"; then
    PYTHON="$(command -v "$candidate")"
    break
  fi
done
[[ -n "$PYTHON" ]] || missing+=("python")

OPENSSL=""
for candidate in "$(command -v openssl || true)" /opt/homebrew/opt/openssl@3/bin/openssl \
  /usr/local/opt/openssl@3/bin/openssl; do
  if [[ -n "$candidate" && -x "$candidate" ]] && openssl_ok "$candidate"; then
    OPENSSL="$candidate"
    break
  fi
done
[[ -n "$OPENSSL" ]] || missing+=("openssl@3")

if ((${#missing[@]})); then
  echo "The demo needs a few free developer tools that this computer does not have yet."
  if command -v brew >/dev/null 2>&1; then
    echo "Install them with:"
    echo
    echo "    brew install ${missing[*]}"
  else
    echo "On a Mac, install Homebrew first (see https://brew.sh), then run:"
    echo
    echo "    brew install ${missing[*]}"
    echo
    echo "On Linux, install Rust from https://rustup.rs and Python 3.10+ and OpenSSL 3"
    echo "from your distribution's packages."
  fi
  echo
  echo "Then run this command again."
  exit 1
fi
export PATH="$(dirname "$OPENSSL"):$PATH"

# Run a build step quietly; on failure, show the end of its output.
step() {
  local label="$1"
  shift
  printf '  %s ... ' "$label"
  if "$@" >>"$LOG" 2>&1; then
    echo "done"
  else
    echo "failed"
    echo
    tail -n 30 "$LOG"
    echo
    echo "The whole build log is in $LOG"
    exit 1
  fi
}

echo "Preparing the demo. The first run builds Stet from source, which takes"
echo "a few minutes and downloads its dependencies; later runs start in seconds."
if ! python_ok "$VENV/bin/python"; then
  step "creating a Python environment" "$PYTHON" -m venv --clear "$VENV"
fi
step "installing the Anthropic and OpenAI SDKs" \
  "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check \
  maturin anthropic openai httpx2
# Build a wheel and install it, rather than `maturin develop`: an editable
# install is a .pth file, which Python 3.13 and later skip when it is marked
# hidden, and iCloud Drive marks every file of a virtual environment hidden
# when the checkout is in Desktop or Documents.
WHEELS="$(mktemp -d -t pragmatic-demo-wheels.XXXXXX)"
step "building the Stet Python SDK" \
  "$VENV/bin/maturin" build --quiet --manifest-path "$ROOT/crates/pragmatic-python/Cargo.toml" \
  --interpreter "$VENV/bin/python" --out "$WHEELS"
wheel=("$WHEELS"/*.whl)
step "installing the Stet Python SDK" \
  "$VENV/bin/python" -m pip install --quiet --disable-pip-version-check \
  --force-reinstall --no-deps "${wheel[0]}"
rm -rf "$WHEELS"
step "building Stet Server and the pragmatic CLI" \
  cargo build --quiet --manifest-path "$ROOT/Cargo.toml" -p pragmatic-server -p pragmatic-cli
rm -f "$LOG"
echo

PRAGMATIC_E2E_SKIP_BUILD=1 exec "$VENV/bin/python" "$DEMO/demo.py" "$@"
