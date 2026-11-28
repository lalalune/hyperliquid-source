"""Verify exact #115 ELF spans and run offline adjacent-state controls."""

import hashlib
from pathlib import Path
import sys

from preflight import SelectorState, U64_MAX, pair

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


# Each line is an instruction or a contiguous instruction span.
SPANS = {
    0x5A0901F: "e89ceeffff",                     # constructor -> selector
    0x5A05FC9: "e8f21e0000",                     # block finalizer -> selector
    0x5A07ED7: "488bb6500400004c8b7e28",         # ctx owner and height
    0x5A07EE2: "48b8917efb3a70ce88d2490fafc748c1c80448b9cc10c7bab88d06004839c8",
    0x5A07F01: "7222",                           # 10000 arm
    0x5A07F03: "83bee81000000175344c39bef0100000",
    0x5A07F13: "0f824a060000",                   # first past-target exit
    0x5A07F19: "400f94c541833e02740beb23",       # equality; mode exit
    0x5A07F25: "40b50141833e02751a",             # 10000 sets flag; mode exit
    0x5A07F2E: "48b80000000000000080488903e911060000",
    0x5A07F40: "31ed41833e0274e6",               # other tag; mode exit
    0x5A07F48: "83bee81000000175134c39bef0100000",
    0x5A07F58: "0f821e060000",                   # second past-target exit
    0x5A07F80: "4084ed7536488b8ec8390000",       # bypass or cadence load
    0x5A07F8C: "4c89f84809c848c1e8207413",       # operand-width selection
    0x5A07F98: "4c89f831d248f7f14885d20f85a8030000eb10",
    0x5A07FAB: "4489f831d2f7f14885d20f8596030000",
    0x5A07FBB: "498d9630030000",                 # raw-root sink argument
    0x5A07FCE: "e8fd5aa8ff",                     # local root
    0x5A07FE2: "4c89fee8b6bfffff",               # same height -> local history
    0x548DBC7: "498b47284889442450",             # writer record height
    0x548DBF9: "e8a2cb9aff",                     # writer call
}


def verify_anchors():
    data = Path(TARGET).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    assert digest == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def read(name, address, size):
        section = sections[name]
        displacement = address - section["va"]
        assert 0 <= displacement <= displacement + size <= section["size"]
        offset = section["offset"] + displacement
        return data[offset:offset + size]

    unwind = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", unwind["va"], unwind["size"]), unwind["va"])
    for address, encoding in SPANS.items():
        raw = bytes.fromhex(encoding)
        assert any(fde["entry"] <= address < address + len(raw) <= fde["end"] for fde in fdes)
        assert read(".text", address, len(raw)) == raw, hex(address)

    def edge(site, length):
        return site + length + int.from_bytes(
            read(".text", site + length - 4, 4), "little", signed=True,
        )

    assert edge(0x5A0901F, 5) == edge(0x5A05FC9, 5) == 0x5A07EC0
    assert edge(0x5A07F13, 6) == 0x5A08563
    assert edge(0x5A07F58, 6) == 0x5A0857C
    assert edge(0x5A07FCE, 5) == 0x548DAD0
    assert edge(0x5A07FE5, 5) == 0x5A03FA0
    assert edge(0x548DBF9, 5) == 0x4E3A7A0
    print(f"PASS: {len(SPANS)} #115 static spans, in FDEs, SHA-256 {digest}")

    limit = U64_MAX + 1
    multiplier = int.from_bytes(read(".text", 0x5A07EE4, 8), "little")
    threshold = int.from_bytes(read(".text", 0x5A07EF6, 8), "little")
    assert multiplier * 625 % limit == 1
    assert threshold == U64_MAX // 10_000 + 1
    largest_multiple = U64_MAX - U64_MAX % 10_000
    heights = (0, 1, 9_999, 10_000, 10_001, (1 << 32) - 1, 1 << 32,
               largest_multiple - 1, largest_multiple, largest_multiple + 1, U64_MAX)
    for height in heights:
        product = height * multiplier & U64_MAX
        rotated = (product >> 4) | ((product & 0xF) << 60)
        assert (rotated < threshold) == (height % 10_000 == 0)
    print(f"PASS: instruction-derived 10000 test against {len(heights)} u64 controls")


def verify_controls():
    standard = SelectorState(0, 0, 0, 1000)
    cases = (
        ("ordinary periodic checkpoint", 10_000, standard, standard,
         ("eligible-10000", "skips-cadence")),
        ("custom cadence changes at H+1", 10_000, standard, SelectorState(0, 0, 0, 73),
         ("eligible-10000", "eligible-periodic")),
        ("target activates at H+1", 10_000, standard, SelectorState(0, 1, 10_001, 1000),
         ("eligible-10000", "eligible-freeze")),
        ("inactive tag cannot trigger", 10_000, standard, SelectorState(0, 2, 10_001, 1000),
         ("eligible-10000", "skips-cadence")),
        ("mode-2 suppresses matching gates", 10_000, SelectorState(2, 0, 0, 1000),
         SelectorState(2, 1, 10_001, 1000), ("skips-mode-2", "skips-mode-2")),
        ("non-10k invariant precedes mode", 10_000, SelectorState(2, 1, 9_999, 1000),
         SelectorState(2, 1, 10_000, 1000), ("skips-mode-2", "invariant-before-mode")),
        ("10k invariant after mode", 10_000, SelectorState(0, 1, 9_999, 1000),
         standard, ("invariant-after-mode", "skips-cadence")),
        ("materialized zero only matters at ordinary division", 10_000,
         SelectorState(0, 0, 0, 0), SelectorState(0, 0, 0, 0),
         ("eligible-10000", "invalid-materialized-cadence")),
        ("wide period", 1 << 32, SelectorState(0, 0, 0, 1 << 32),
         SelectorState(0, 0, 0, 1 << 32), ("eligible-periodic", "skips-cadence")),
    )
    for label, height, at_h, at_h1, expected in cases:
        actual = pair(height, at_h, at_h1)
        assert actual == expected, (label, actual, expected)
        print(f"PASS: {label}: H={actual[0]} H+1={actual[1]}")
    for height, at_h in ((-1, standard), (U64_MAX, standard),
                         (10_000, SelectorState(1 << 32, 0, 0, 1000))):
        try:
            pair(height, at_h, standard)
        except ValueError:
            pass
        else:
            raise AssertionError((height, at_h))
    print("PASS: three out-of-range inputs rejected")


if __name__ == "__main__":
    assert __debug__, "run without -O"
    verify_anchors()
    verify_controls()
