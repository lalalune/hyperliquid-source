#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
for tool in git python3 rg gpg rustup git-lfs; do
  command -v "$tool" >/dev/null || { echo "Missing prerequisite: $tool" >&2; exit 1; }
done
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
git lfs version
git lfs install --local
git submodule update --init --recursive
git lfs pull
git -C references/can1357-hl lfs pull
rustup toolchain install 1.94.1 --profile minimal --component rustfmt,clippy --no-self-update
rustup toolchain install 1.95.0 --profile minimal --component rustfmt,clippy --no-self-update
python3 tools/artifacts.py verify
