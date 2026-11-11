#!/usr/bin/env python3
"""Verify recorded abstraction-kind call argument evidence."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('abstraction_call_abi', HERE / 'collect.py')
module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(module)


def main():
    actual = module.extract()
    recorded = json.loads((HERE / 'records.json').read_text())
    if actual != recorded:
        raise SystemExit('records differ from regenerated target evidence')
    print(f"verified calls={len(actual['calls'])} visitors={len({row['visitor_entry'] for row in actual['calls']})}")


if __name__ == '__main__':
    main()
