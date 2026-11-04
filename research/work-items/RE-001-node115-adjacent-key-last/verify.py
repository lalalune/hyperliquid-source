#!/usr/bin/env python3
"""Verify the exact adjacent-key-last packet whitelist and regenerate its evidence."""
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = next(p for p in Path(__file__).resolve().parents
            if (p / 'tools/node115_adjacent_key_last.py').is_file())
sys.path.insert(0, str(ROOT / 'tools'))
from node115_adjacent_key_last import verify_packet

if __name__ == '__main__':
    try:
        verify_packet(Path(__file__).resolve().parent)
    except (ValueError, OSError) as error:
        print(f'verification failed: {error}', file=sys.stderr)
        raise SystemExit(1)
    print('node #115 adjacent-key-last: whitelist, hashes and regeneration passed')
