"""Bind the two log height projections to the same numeric writer in node #115."""
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from freeze_snapshot_115 import fixed, read_va, rip_target


def check_height(data):
    # Each caller selects its own height slot before the common field writer.
    fixed(data, 0x537D617, "488d4b08")
    fixed(data, 0x537D7E7, "488d4b20")
    for va in (0x537D61B, 0x537D7EB):
        if read_va(data, rip_target(data, va, b"\x48\x8d\x35", 7), 6) != b"height":
            raise ValueError("unexpected field name")
    for va, target in ((0x537D62C, 0x5077210), (0x537D7FC, 0x5077210),
                       (0x50772C2, 0x50FC010)):
        if rip_target(data, va, b"\xe8", 5) != target:
            raise ValueError(f"call target at {va:#x}")
    fixed(data, 0x5077227, "4889cb")  # preserve rcx, the selected field address
    fixed(data, 0x507729A, "488b3b")  # read its u64 value into rdi
    fixed(data, 0x50772B1, "c604303a")  # emit ':'
    fixed(data, 0x50772BF, "4889e6")  # pass scratch as rsi
    fixed(data, 0x50FC011, "b814000000")  # 20 decimal digits cover u64::MAX
    fixed(data, 0x50FC016, "4881ff10270000")  # split at 10,000
    pairs = rip_target(data, 0x50FC032, b"\x4c\x8d\x0d", 7)
    if read_va(data, pairs, 200) != b"".join(f"{i:02}".encode() for i in range(100)):
        raise ValueError("decimal digit-pair table mismatch")
    fixed(data, 0x50FC0C5, "80ca30")  # one leading digit


if __name__ == "__main__":
    node = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    if hashlib.sha256(node).hexdigest() != "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301":
        raise ValueError("node #115 digest mismatch")
    check_height(node)
    print("two height fields, one u64 writer, 100 decimal digit pairs")
