#!/usr/bin/env python3
"""Generate price-only fixtures from the pure TWAP slice specification."""

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tools import twap_slice_115 as model


OUTPUT = Path(__file__).with_name("price-vectors.tsv")


def main():
    rows = ["family\tside\ttop_bid\ttop_ask\tspot_mid\ttick\texpected_price"]
    for copy in range(4):
        family = model.COPIES[copy]["family"]
        for case in model.cases_for(copy, 2800):
            result = model.spec_slice(copy, case)
            if result.get("tag") != 1:
                continue
            values = (
                family,
                case.order.side,
                case.top[0],
                case.top[1],
                case.mid,
                case.tick,
                struct.unpack("<Q", result["fields"][0x20])[0],
            )
            rows.append("\t".join(map(str, values)))
    OUTPUT.write_text("\n".join(rows) + "\n")
    print(f"wrote {len(rows) - 1} price vectors from spec_slice; no image or evaluator used")


if __name__ == "__main__":
    main()
