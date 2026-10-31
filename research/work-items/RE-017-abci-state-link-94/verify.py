#!/usr/bin/env python3
"""Regenerate RE-017 with the tool and compare to the committed packet, exactly."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import abci_state_link as tool  # noqa: E402

PACKET_JSON = HERE / 'abci-state-link.json'
JSON_SHA256 = 'e8e24678b2e9aa32e93a08f5ab9e469b49b40742d2839affb1c9c2295ace4548'


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
    print(f"verify: keys={len(result['key_bytes'])} targets={len(result['targets'])} "
          f"ff15_mat={len(cs['ff15_slot_sites']['0x5773aa8'])} ff15_fn={len(cs['ff15_slot_sites']['0x57755a8'])} "
          f"rel32_fn={len(cs['rel32_call_sites']['0x3273810'])} errors={len(errors)}")
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
