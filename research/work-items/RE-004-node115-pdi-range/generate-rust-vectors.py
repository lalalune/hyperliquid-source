#!/usr/bin/env python3
"""Generate frozen PDI-range iterator cases from the selected native relation."""

from pathlib import Path

OUTPUT = Path(__file__).resolve().parent / "pdi-range-vectors.tsv"
MAX = (1 << 64) - 1
MAX_COUNT = (1 << 60) - 1
MULTIPLIER = 10_000


def classify(start: int, end: int, base: int, index: int) -> tuple[str, str]:
    count = max(end - start, 0)
    if count > MAX_COUNT:
        return "range", ""
    if index >= count:
        return "out_of_range", ""
    product = base * MULTIPLIER
    if product > MAX:
        return "multiply", ""
    tail = start + index
    if tail > MAX:
        return "add", ""
    value = product + tail
    if value > MAX:
        return "add", ""
    return "ok", str(value)


def rows() -> list[tuple[int, int, int, int, str, str]]:
    threshold = MAX // MULTIPLIER
    cases = [
        (0, 0, 0),
        (10, 10, threshold),
        (10, 9, threshold + 1),
        (10, 14, 3),
        (0, 1, threshold),
        (0, 1, threshold + 1),
        (MAX - 1, MAX, threshold),
        (0, 2000, threshold),
        (0, MAX_COUNT, 0),
        (0, MAX_COUNT + 1, 0),
        (1, MAX, 7),
        (MAX, MAX, MAX),
    ]
    output = []
    for start, end, base in cases:
        count = max(end - start, 0)
        indexes = {0, max(count - 1, 0), count, 1615, 1616}
        for index in sorted(indexes):
            result, value = classify(start, end, base, index)
            output.append((start, end, base, index, result, value))
    return output


def main() -> None:
    lines = ["start\tend\tbase\tindex\tresult\tvalue"]
    lines.extend(
        f"{start}\t{end}\t{base}\t{index}\t{result}\t{value}"
        for start, end, base, index, result, value in rows()
    )
    OUTPUT.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    print(f"wrote {len(lines) - 1} cases")


if __name__ == "__main__":
    main()
