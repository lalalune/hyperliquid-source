#!/usr/bin/env python3
"""Regenerate RE-016 with the tool and compare to the committed packet, exactly."""
import hashlib
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
import state_chain as tool  # noqa: E402

PACKET_JSON = HERE / 'state-chain.json'
JSON_SHA256 = '6e063821c3de3ad62dc45b0af1bc28ff7cdedaf048da0fbdd3cc5e51cabead75'


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
    f = result['functions']
    print(f"verify: edges={len(result['edges'])} relocs={len(result['relocations'])} "
          f"copies={len(result['output_copies'])} insns={sum(v['instructions'] for v in f.values())} "
          f"rela_entries={result['rela_dyn']['entries']} errors={len(errors)}")
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
