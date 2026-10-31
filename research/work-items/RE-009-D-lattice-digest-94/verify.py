#!/usr/bin/env python3
"""Regenerate RE-009-D with the tool and compare to the committed packet, exactly."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import lattice_digest as tool  # noqa: E402

PACKET_JSON = HERE / 'lattice-digest.json'
JSON_SHA256 = '53d36b84f3f5cca3821964e1670abdf38ff389d2b62a5b4e75d6f993f74860a0'


def main():
    result = tool.analyse(tool.TARGET.read_bytes())
    text = tool.render(result)
    errors = list(tool.expectation_errors(result))
    if hashlib.sha256(text.encode()).hexdigest() != JSON_SHA256:
        errors.append('regenerated output sha256 mismatch')
    if PACKET_JSON.read_text() != text:
        errors.append('committed json differs from regenerated output')
    d = result['digest_function']
    for e in errors:
        print('FAIL', e)
    print(f"verify: lanes={len(d['hasher_runs'])} update_len=0x800x3 fields={len(d['output_fields'])} "
          f"struct={d['output_size']} unhashed_trailers={len(d['unhashed_trailers'])} "
          f"callers={len(result['callers'])} writer_args={len(result['writer']['arguments_read'])} "
          f"errors={len(errors)}")
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
