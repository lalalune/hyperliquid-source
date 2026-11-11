#!/usr/bin/env python3
"""Generate frozen heartbeat ratio/age classification vectors."""

import math
import struct
from pathlib import Path

OUTPUT = Path(__file__).resolve().parent / "heartbeat-vectors.tsv"


def bits(value: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def value(raw: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", raw))[0]


def classify(
    found: bool,
    numerator: float,
    denominator: float,
    threshold: float,
    flag: bool,
    age: float,
) -> tuple[str, str]:
    if not found:
        return "missing", "0"
    if denominator == 0.0:
        ratio = 0.0
    elif not denominator > 0.0:
        return "error", "-"
    else:
        ratio = numerator / denominator
    if ratio == 0.0:
        cleaned = ratio
    elif ratio > 0.0 and math.isfinite(ratio):
        cleaned = ratio
    else:
        cleaned = 0.0
    if cleaned > threshold and not flag:
        return "ratio", str(bits(cleaned))
    if age > 180.0:
        return "age", str(bits(age))
    return "skip", "3"


def rows() -> list[tuple[bool, int, int, int, bool, int, str, str]]:
    values = [
        0.0,
        -0.0,
        1.0,
        -1.0,
        180.0,
        180.00000000000003,
        math.inf,
        -math.inf,
        math.nan,
    ]
    numerators = [0.0, -0.0, 1.0, -1.0, 181.0, math.inf, -math.inf, math.nan]
    denominators = [0.0, -0.0, 1.0, 2.0, -1.0, math.inf, -math.inf, math.nan]
    output = []
    output.append(
        (
            False,
            bits(1.0),
            bits(1.0),
            bits(0.5),
            False,
            bits(999.0),
            "missing",
            "0",
        )
    )
    for numerator in numerators:
        for denominator in denominators:
            for threshold in (0.5, 180.0):
                for flag in (False, True):
                    for age in (values[4], values[5], values[6], values[8]):
                        result, payload = classify(
                            True, numerator, denominator, threshold, flag, age
                        )
                        output.append(
                            (
                                True,
                                bits(numerator),
                                bits(denominator),
                                bits(threshold),
                                flag,
                                bits(age),
                                result,
                                payload,
                            )
                        )
    return output


def main() -> None:
    lines = [
        "found\tnumerator_bits\tdenominator_bits\tthreshold_bits\tflag\tage_bits\tresult\tpayload"
    ]
    lines.extend(
        f"{int(found)}\t{numerator}\t{denominator}\t{threshold}\t{int(flag)}\t{age}\t{result}\t{payload}"
        for found, numerator, denominator, threshold, flag, age, result, payload in rows()
    )
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    print(f"wrote {len(lines) - 1} cases")


if __name__ == "__main__":
    main()
