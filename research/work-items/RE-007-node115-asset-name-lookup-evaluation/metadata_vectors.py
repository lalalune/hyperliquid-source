"""Print ordered-name lookup vectors for the integrated perpetual metadata type."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
import pdi_name_lookup115 as lookup


def main():
    image = lookup.TARGET.read_bytes()
    if lookup.sha256(image) != lookup.TARGET_SHA256:
        raise ValueError("unexpected node release")
    sections = lookup.sections(image)
    start = lookup.va_to_offset(sections, lookup.BODY_START)
    body = image[start : start + lookup.BODY_END - lookup.BODY_START]
    if lookup.sha256(body) != lookup.BODY_SHA256:
        raise ValueError("unexpected lookup body")
    instructions = lookup.decode_body(body)
    slots = lookup.slot_targets(image, sections)
    tables = [
        (0, []),
        (0, ["BTC", "ETH", "SOL"]),
        (7, ["ETH", "GOLD", "ETH", ""]),
        (9, ["X", "Ξ", "É", "E\u0301"]),
        (11, ["PERP", "PERP1", "PERP10"]),
    ]
    queries = ["", "BTC", "ETH", "eth", "ETH ", "SOL", "GOLD", "X", "Ξ", "É", "E\u0301", "PERP1", "PERP10"]
    print("page\trecords\tnames\tsuffix\tresult")
    for page, names in tables:
        records = [(value.encode(), len(value.encode())) for value in names]
        for suffix in queries:
            encoded = suffix.encode()
            case = lookup.Fixture(records, encoded, page)
            result = lookup.run_body(instructions, case, slots)
            outcome = lookup.outcome_of(result)
            if outcome[0] == "ok":
                value = str(outcome[1])
            elif outcome[0] == "err" and result.get("heap", b"") == encoded:
                value = "missing"
            else:
                raise ValueError((page, names, suffix, outcome))
            print(page, len(names), "|".join(names), suffix, value, sep="\t")


if __name__ == "__main__":
    main()
