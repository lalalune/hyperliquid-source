#!/usr/bin/env python3
"""Regenerate RE-018 with the tool and compare to the committed packet, exactly."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import materializer_call_abi as tool  # noqa: E402

PACKET_JSON = HERE / 'materializer-call-abi.json'
JSON_SHA256 = '4789cdd0cb2dd7af93b0a20b50cd976da3b3fc18fe0307505d0b25a98c6f52f0'


def main():
    result = tool.analyse(tool.TARGET.read_bytes())
    text = tool.render(result)
    errors = list(tool.expectation_errors(result))
    if hashlib.sha256(text.encode()).hexdigest() != JSON_SHA256:
        errors.append('regenerated output sha256 mismatch')
    if PACKET_JSON.read_text() != text:
        errors.append('committed json differs from regenerated output')
    for e in errors:
        print('FAIL', e)
    cs = result['caller_scan']
    print(f"verify: key_insns={len(result['key_bytes'])} sites={len(result['sites'])} "
          f"ff15={len(cs['ff15_slot_sites']['0x5773aa8'])} windows={len(result['window_sha256'])} "
          f"errors={len(errors)}")
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
