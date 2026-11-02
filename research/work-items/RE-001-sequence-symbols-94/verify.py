#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Whitelist and reproduce this packet using the authenticated static target."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'tools'))
from sequence_symbol_streams import main

if __name__ == '__main__':
    raise SystemExit(main(['--check', str(Path(__file__).resolve().parent)]))
