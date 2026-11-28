"""Compare Rust fields and rest/error with the packet's independently tested rule list."""
import itertools
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import chrono_rfc2822_parse_115 as oracle


def cases():
    names = ("empty", "year", "second", "offset", "weekday")
    for i, (date, time, zone, suffix) in enumerate(itertools.product(
        ("Tue, 02 Jan 2024", "1 Dec 49", "31 MAR 50", "tHU, 1 Aug 100", "5\u00a0may\u20090050"),
        ("00:00", "23:59:60", "11 : 03 :00", "12:34:56", "24:00", "11:60"),
        ("GMT", "ut", "EST", "pdt", "A", "J", "+0000", "-0530", "+9959", "+1160"),
        ("", " (a (b))  x", " (x\\)y)(done)", " (unclosed", "!more"),
    )):
        yield names[i % len(names)], f"{date} {time} {zone}{suffix}"
    sample = "Tue, 02 Jan 2024 23:45:59 -0530 (comment)"
    yield from (("empty", sample[:i]) for i in range(len(sample) + 1))
    for value in ["00", "1", "32", "000", "2147483648", "9223372036854775808"]:
        yield "empty", f"2 Jan {value} 12:00 GMT"


def outcome(preset, text):
    initial = {
        "empty": [], "year": [(oracle.F_YEAR, oracle.word(1, 2024))],
        "second": [(oracle.F_SECOND, oracle.word(1, 0))],
        "offset": [(oracle.F_OFFSET, oracle.word(1, -18000))],
        "weekday": [(oracle.F_WEEKDAY, bytes([1]))],
    }
    data = text.encode()
    state = oracle.initial_state(oracle.Case(oracle.P2822, data, pre=initial[preset]))
    kind, n = oracle.Spec().parse(data, state)
    fields = []
    for field in oracle.FIELDS:
        flag, value = struct.unpack_from("<Ii", state, field)
        fields.append(str(value) if flag == 1 else "-")
    weekday = state[oracle.F_WEEKDAY]
    fields.append(str(weekday) if weekday != 7 else "-")
    return f"{kind}:{n} " + " ".join(fields)


def main():
    inputs = list(cases())
    with tempfile.TemporaryDirectory() as temp:
        probe = Path(temp) / "probe"
        subprocess.run(["rustc", "--edition=2021", str(HERE / "fields_probe.rs"), "-o", str(probe)], check=True)
        raw = "".join(f"{pre} {text.encode().hex()}\n" for pre, text in inputs)
        rows = subprocess.check_output([probe], input=raw, text=True).splitlines()
    for (pre, text), got in zip(inputs, rows, strict=True):
        expected = outcome(pre, text)
        if got != expected:
            raise ValueError((pre, text, got, expected))
    print(f"Matched {len(rows)} parsed outcomes, consumed byte counts and partial records.")


if __name__ == "__main__":
    main()
