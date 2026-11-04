#!/usr/bin/env python3
"""Generate frozen scalar lookup cases from the selected native relation."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = Path(__file__).resolve().parent / "target-smoke.tsv"


def scan(keys: list[int], query: int) -> tuple[str, int | str]:
    for index, key in enumerate(keys):
        if query > key:
            continue
        if query == key:
            return "found", index
        return "missing", ""
    return "missing", ""


def rows() -> list[tuple[str, int, int, str, int | str]]:
    cases = [
        ("empty", []),
        ("single_zero", [0]),
        ("single_255", [255]),
        ("edges", [0, 127, 128, 255]),
        ("all_bytes", list(range(256))),
    ]
    output = []
    for name, keys in cases:
        for query in range(256):
            result, value_index = scan(keys, query)
            output.append((name, 1, query, result, value_index))
    for name, keys, query, height in [
        ("height_zero_hit", [7, 9], 7, 0),
        ("height_zero_miss", [7, 9], 8, 0),
        ("high_bits_low_zero", [0, 255], 0x100, 1),
        ("high_bits_low_ff", [0, 255], 0x1FF, 1),
    ]:
        result, value_index = scan(keys, query & 0xFF)
        output.append((name, height, query, result, value_index))
    return output


def main() -> None:
    lines = ["case\theight\tquery\tresult\tvalue_index"]
    lines.extend(
        f"{case}\t{height}\t{query}\t{result}\t{value_index}"
        for case, height, query, result, value_index in rows()
    )
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    print(f"wrote {len(lines) - 1} cases to {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
