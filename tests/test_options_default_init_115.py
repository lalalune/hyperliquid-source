"""Tests for tools/options_default_init_115.py.

Run directly (pytest is not installed on this VM):
    python3 tests/test_options_default_init_115.py

Every check is a target-grounded expectation: field values are
the exact stores in the verbatim excerpts of the
RE-001-options-default-init-115 packet, and the site lists are
the census in that packet's callers.tsv.
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import options_default_init_115 as model

CHECKS = [0]


def check(name, cond):
    CHECKS[0] += 1
    if not cond:
        raise AssertionError("check failed: %s" % name)
    print("ok %d: %s" % (CHECKS[0], name))


def main():
    base = model.base_init()
    opts = model.default_init()
    after = model.apply_preset(model.default_init())
    heap = model.table_copy()

    # Base init defaults.
    check("base +0x20 is 10000", base[0x20] == 0x2710)
    check("base +0x98 is 64 MiB", base[0x98] == 0x4000000)
    check("base +0xa8 is the double 10.0",
          struct.unpack("<d", struct.pack("<Q", base[0xA8]))[0] == 10.0)
    check("base +0x108 is 1 GiB", base[0x108] == 0x40000000)
    check("base +0x90 is 0x24", base[0x90] == 0x24)
    check("base +0xa4 is 0x100", base[0xA4] == 0x100)
    check("base +0xe8 is 0x300", base[0xE8] == 0x300)
    check("base +0xfc is 0x1ffffffff", base[0xFC] == 0x1FFFFFFFF)
    check("base +0x158 is 0x1000100", base[0x158] == 0x1000100)
    check("base +0x00 packs two i32s (2, 1)",
          base[0x00] == 0x100000002)
    check("base +0x88 packs two i32s (7, 20)",
          base[0x88] == 0x1400000007)
    d0, d1 = struct.unpack("<dd", bytes.fromhex(base[0x1B0][1]))
    check("base +0x1b0 doubles are (0.25, 1.0)", (d0, d1) == (0.25, 1.0))
    q0, q1 = struct.unpack("<QQ", bytes.fromhex(base[0xD8][1]))
    check("base +0xd8 qwords are 64 GiB, 256 GiB",
          (q0, q1) == (0x1000000000, 0x4000000000))
    check("base +0xb0 is the 0x1c-byte heap object",
          base[0xB0] == ("ptr", "heap1c"))
    check("base +0xb8/+0xc0 point 0x1c into that object",
          base[0xB8] == base[0xC0] == ("ptr", "heap1c+0x1c"))
    check("base +0x128 is the 0x28-byte heap object",
          base[0x128] == ("ptr", "heap28"))
    check("base +0x130 is the 0x18-byte heap object",
          base[0x130] == ("ptr", "heap18a"))
    check("base zero fields are zero",
          all(base[o] == 0 for o in
              (0x08, 0x10, 0x18, 0x28, 0x30, 0x38, 0x40, 0x48,
               0x60, 0x68, 0x80, 0xC8, 0x104, 0x110, 0x148, 0x150,
               0x15C, 0x170, 0x178, 0x190, 0x1A8, 0x1C0, 0x1C8,
               0x1E0, 0x1E4)))
    check("base 16-byte zero blocks are zero",
          all(base[o] == ("bytes", "00" * 16) for o in
              (0x50, 0x70, 0x138, 0x180, 0x1D0)))

    # Main init defaults.
    check("main +0x1e8 is the singleton pointer",
          opts[0x1E8] == ("ptr", "singleton61be810"))
    check("main +0x218 is 64 MiB", opts[0x218] == 0x4000000)
    check("main +0x220 is 0xff01", opts[0x220] == 0xFF01)
    check("main +0x228 is 0x7ffffffffff2",
          opts[0x228] == 0x7FFFFFFFFFF2)
    check("main +0x238 is 4 GiB", opts[0x238] == 0x100000000)
    check("main +0x258 repeats the 0x7ffffffffff2 limit",
          opts[0x258] == 0x7FFFFFFFFFF2)
    check("main +0x268 is 4 GiB", opts[0x268] == 0x100000000)
    check("main +0x288 is 4", opts[0x288] == 0x4)
    q0, q1 = struct.unpack("<QQ", bytes.fromhex(opts[0x2A0][1]))
    check("main +0x2a0 qwords are 256 MiB, 0", (q0, q1) == (0x10000000, 0))
    check("main +0x2b8 is the 0x260-byte table-options object",
          opts[0x2B8] == ("ptr", "heap260"))
    check("main +0x2c0 is the 0x18-byte holder object",
          opts[0x2C0] == ("ptr", "heap18b"))
    check("main zero fields are zero",
          all(opts[o] == 0 for o in
              (0x1F0, 0x1F8, 0x200, 0x208, 0x210, 0x230, 0x240,
               0x248, 0x260, 0x270, 0x278, 0x2B0, 0x2F8)))
    check("main spans +0x00..+0x2f8 with no gap in the model",
          set(opts) == set(model.BASE_FIELDS) | set(model.MAIN_FIELDS))

    # Preset overrides.
    check("preset +0x218 shrinks 64 MiB to 2 MiB",
          after[0x218] == 0x200000)
    check("preset +0x98 shrinks 64 MiB to 2 MiB",
          after[0x98] == 0x200000)
    check("preset +0x2a0 shrinks 64 GiB to 10 MiB",
          after[0x2A0] == 0xA00000)
    check("preset +0x220 low byte clears: 0xff01 -> 0xff00",
          after[0x220] == 0xFF00)
    q0, q1 = struct.unpack("<QQ", bytes.fromhex(after[0xD8][1]))
    check("preset +0xd8 qwords are 256 MiB, 1 GiB",
          (q0, q1) == (0x10000000, 0x40000000))
    check("preset leaves the other fields alone",
          all(after[o] == opts[o] for o in opts
              if o not in model.PRESET_OVERRIDES))
    check("preset touches exactly five fields",
          len(model.PRESET_OVERRIDES) == 5)

    # Stack temp built by the main init.
    check("temp +0x28 double is 0.75",
          model.temp_double(0x28) == 0.75)
    check("temp +0x30 u16 is 4",
          model.temp_u64(0x30) & 0xFFFF == 4)
    check("temp +0x10 u32 is 0x01000100",
          model.temp_u64(0x10) & 0xFFFFFFFF == 0x01000100)
    check("temp +0x59/+0x64/+0x71 magic qwords",
          model.temp_u64(0x59) == 0x0A00000000000010
          and model.temp_u64(0x64) == 0x0000000100000010
          and model.temp_u64(0x71) == 0x0200000000000010)
    check("temp +0x90 list head is null (walk skipped)",
          model.temp_u64(0x90) == 0)
    check("temp +0x98/+0xa0 are self-pointers to temp+0x88",
          model.build_table_temp()[0x98] == ("ptr", "temp+0x88")
          and model.build_table_temp()[0xA0] == ("ptr", "temp+0x88"))
    check("temp +0xd8 is 0x40000 (256 KiB)",
          model.temp_u64(0xD8) == 0x40000)
    check("temp +0xd0 is 5", model.temp_u64(0xD0) & 0xFFFFFFFF == 5)

    # Table-options copy from the default temp.
    check("table heap vtable is 0x64d39b8",
          heap[0x00] == ("ptr", "vtable64d39b8"))
    check("table +0x30 is 0x01000100", heap[0x30] == 0x01000100)
    check("table +0x48 double is 0.75", heap[0x48] == 0.75)
    check("table +0x50 is 4", heap[0x50] == 4)
    check("table +0x78 is 0x1000", heap[0x78] == 0x1000)
    check("table +0x80 is 0x100000000a", heap[0x80] == 0x100000000A)
    check("table +0x88 is 1", heap[0x88] == 1)
    check("table +0x90 is 0x1000", heap[0x90] == 0x1000)
    check("table +0x98 is 2", heap[0x98] == 2)
    check("table +0xb0 is null (empty tree root)",
          heap[0xB0] == ("bytes", "00" * 8))
    check("table +0xb8/+0xc0 are self-pointers to heap+0xa8",
          heap[0xB8] == heap[0xC0] == ("ptr", "heap+0xa8"))
    check("table +0xc8 is 0", heap[0xC8] == 0)
    check("table +0xd2 is 1", heap[0xD2] == 1)
    check("table +0xe8 is 1", heap[0xE8] == 1)
    check("table +0xf4 is 1", heap[0xF4] == 1)
    check("table +0xf6 is 1", heap[0xF6] == 1)
    check("table +0xf8 is 0x40000", heap[0xF8] == 0x40000)
    check("table +0x108 carries the 0x4506c0 constant",
          heap[0x108] == ("bytes", "00200000000000000200000000000000"))
    check("table +0x118/+0x250 are zero blocks",
          heap[0x118] == ("bytes", "00" * 16)
          and heap[0x250] == ("bytes", "00" * 16))

    # Call-site classification.
    check("init has 13 direct call sites",
          len(model.INIT_CALLS) == 13)
    check("preset has 3 direct call sites",
          len(model.PRESET_CALLS) == 3)
    check("exactly 3 pair sites", len(model.PAIR_SITES) == 3)
    check("10 init-only sites", len(model.INIT_ONLY_SITES) == 10)
    check("pair sites are a subset of init sites",
          all(p[0] in model.INIT_CALLS for p in model.PAIR_SITES))
    check("pair sites are disjoint from init-only sites",
          not set(p[0] for p in model.PAIR_SITES)
          & set(model.INIT_ONLY_SITES))
    check("pair callers are 0x5e5a8c0, 0x5e61ad0, 0x5fa47e0",
          [p[2] for p in model.PAIR_SITES] ==
          [0x5E5A8C0, 0x5E61AD0, 0x5FA47E0])
    check("digest is the node #115 provenance digest",
          model.DIGEST ==
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    print("all %d checks passed" % CHECKS[0])


if __name__ == "__main__":
    main()
