#!/usr/bin/env python3
"""Provider-selectable entry point for the unchanged pre-Rust static derivation."""
import argparse
import subprocess
from pathlib import Path

import evidence as e


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--gnu', default=e.GNU)
    parser.add_argument('--llvm', default=e.LLVM)
    parser.add_argument('--readelf', default=e.READELF)
    args = parser.parse_args()
    e.GNU, e.LLVM, e.READELF = args.gnu, args.llvm, args.readelf
    try:
        e.need(not args.output.exists(), 'preserve existing output')
        e.write_new(args.output, e.collect())
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        parser.exit(1, str(error) + '\n')
