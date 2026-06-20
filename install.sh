#!/usr/bin/env bash
#
# install.sh — set up minisoc for local use / development.
#
# Creates a virtualenv, installs the package (editable, with dev deps), runs a
# quick smoke test, and optionally symlinks the `minisoc` command onto your PATH.
# Safe to re-run: an existing .venv is reused unless you pass --recreate.
#
# On Debian-based systems (Kali, Ubuntu, ...) the standard-library venv/ensurepip
# support ships in a separate package; if it is missing this script installs the
# matching python3-venv package via apt so the install can proceed.
#
# Usage:
#   ./install.sh                 # set up .venv and install
#   ./install.sh --symlink       # also link minisoc into ~/.local/bin
#   ./install.sh --recreate      # delete and rebuild .venv from scratch
#   ./install.sh --no-test       # skip the post-install pytest smoke check
#   ./install.sh --help          # show this help and exit
#
set -euo pipefail

usage() {
  cat <<'EOF'
install.sh — create a virtualenv and install minisoc (editable, with dev deps).

Usage:
  ./install.sh                 # set up .venv and install
  ./install.sh --symlink       # also link minisoc into ~/.local/bin
  ./install.sh --recreate      # delete and rebuild .venv from scratch
  ./install.sh --no-test       # skip the post-install pytest smoke check
  ./install.sh --help          # show this help and exit

On Debian-based systems (Kali, Ubuntu) this installs the matching python3-venv
apt package automatically if virtualenv support is missing.
EOF
}

# All paths resolve against the repo root (this script's directory) so it works
# no matter where it is invoked from.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

VENV_DIR="$REPO_ROOT/.venv"
MIN_PY_MAJOR=3
MIN_PY_MINOR=12

DO_SYMLINK=0
DO_RECREATE=0
DO_TEST=1
for arg in "$@"; do
  case "$arg" in
    --symlink)   DO_SYMLINK=1 ;;
    --recreate)  DO_RECREATE=1 ;;
    --no-test)   DO_TEST=0 ;;
    -h|--help)
      usage
      exit 0 ;;
    *)
      echo "install.sh: unknown option '$arg' (try --help)" >&2
      exit 2 ;;
  esac
done

say()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# 1. Find a Python interpreter that satisfies the >=3.12 floor from pyproject.toml.
find_python() {
  for candidate in python3.13 python3.12 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1; then
      if "$candidate" -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= ($MIN_PY_MAJOR, $MIN_PY_MINOR) else 1)" 2>/dev/null; then
        echo "$candidate"
        return 0
      fi
    fi
  done
  return 1
}

say "Checking for Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ ..."
PYTHON="$(find_python)" || die "need Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ on PATH; none found. Install it and re-run."
say "Using $("$PYTHON" --version 2>&1) at $(command -v "$PYTHON")"

# 1b. Make sure the interpreter can actually build a virtualenv with pip.
# Debian-based distros (Kali, Ubuntu) ship the stdlib `venv`/`ensurepip` support
# in a separate `python3.X-venv` package that is NOT installed by default, so a
# plain `python3 -m venv` aborts with "ensurepip is not available". Detect that
# and install the right package via apt before we try to create the venv.
ensure_venv_support() {
  if "$PYTHON" -c 'import ensurepip' >/dev/null 2>&1; then
    return 0  # venv can bootstrap pip already (Arch/Fedora/macOS, or pkg installed)
  fi

  # Name of the apt package that matches THIS interpreter, e.g. python3.13-venv.
  local pkg
  pkg="$("$PYTHON" -c 'import sys; print("python%d.%d-venv" % sys.version_info[:2])')"

  if ! command -v apt-get >/dev/null 2>&1; then
    die "Python is missing venv/ensurepip support and this is not an apt-based
       system, so it can't be fixed automatically. Install your distro's venv
       package for $("$PYTHON" --version 2>&1) (Debian/Kali: 'sudo apt install $pkg') and re-run."
  fi

  local APT
  if [ "$(id -u)" -eq 0 ]; then
    APT="apt-get"
  elif command -v sudo >/dev/null 2>&1; then
    APT="sudo apt-get"
  else
    die "Python venv support is missing. Install it as root and re-run:
       apt install $pkg"
  fi

  warn "Python venv support is missing (no ensurepip) — normal on a fresh Kali/Debian."
  say "Installing '$pkg' via apt (may prompt for your sudo password) ..."
  $APT update -y >/dev/null 2>&1 || true
  if ! $APT install -y "$pkg"; then
    die "automatic install of '$pkg' failed. Install it manually and re-run:
       sudo apt install $pkg"
  fi

  "$PYTHON" -c 'import ensurepip' >/dev/null 2>&1 \
    || die "'$pkg' was installed but ensurepip is still unavailable; please open an issue."
  say "venv support installed."
}

# 2. Create (or reuse) the virtualenv.
if [ "$DO_RECREATE" -eq 1 ] && [ -d "$VENV_DIR" ]; then
  say "Removing existing virtualenv (--recreate) ..."
  rm -rf "$VENV_DIR"
fi
if [ -d "$VENV_DIR" ]; then
  say "Reusing existing virtualenv at .venv (pass --recreate to rebuild)"
else
  ensure_venv_support
  say "Creating virtualenv at .venv ..."
  "$PYTHON" -m venv "$VENV_DIR" || die "failed to create venv (is the python venv module installed?)"
fi

VENV_PY="$VENV_DIR/bin/python"

# 3. Install minisoc and its dev/test dependencies (editable).
say "Upgrading pip ..."
"$VENV_PY" -m pip install --quiet --upgrade pip
say "Installing minisoc (editable, with dev deps) ..."
"$VENV_PY" -m pip install --quiet -e ".[dev]"

# 4. Smoke test: the console command resolves and the suite passes.
if [ "$DO_TEST" -eq 1 ]; then
  say "Running smoke test (minisoc list) ..."
  "$VENV_DIR/bin/minisoc" list >/dev/null || die "the 'minisoc' command failed to run after install"
  say "Running test suite (pytest) ..."
  if ! "$VENV_PY" -m pytest -q; then
    warn "tests reported failures — install is usable but review the output above"
  fi
else
  say "Skipping tests (--no-test)"
fi

# 5. Optional: symlink the command onto the user's PATH.
if [ "$DO_SYMLINK" -eq 1 ]; then
  LINK_DIR="$HOME/.local/bin"
  mkdir -p "$LINK_DIR"
  ln -sf "$VENV_DIR/bin/minisoc" "$LINK_DIR/minisoc"
  say "Linked minisoc -> $LINK_DIR/minisoc"
  case ":$PATH:" in
    *":$LINK_DIR:"*) : ;;
    *) warn "$LINK_DIR is not on your PATH — add it to use 'minisoc' without activating the venv" ;;
  esac
fi

# 6. Tell the user how to activate, picking the hint that matches their shell.
ACTIVATE="source $VENV_DIR/bin/activate"
case "${SHELL:-}" in
  */fish) ACTIVATE="source $VENV_DIR/bin/activate.fish" ;;
  */csh|*/tcsh) ACTIVATE="source $VENV_DIR/bin/activate.csh" ;;
esac

cat <<EOF

$(printf '\033[1;32m✓ minisoc installed.\033[0m')

  Activate the environment:   $ACTIVATE
  Then try:                   minisoc list
                              minisoc run --scenario ssh-bruteforce
                              minisoc serve          # dashboard at http://127.0.0.1:8000
EOF
