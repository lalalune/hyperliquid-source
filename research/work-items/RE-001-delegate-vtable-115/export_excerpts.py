#!/usr/bin/env python3
"""Export the verbatim objdump excerpts for the RE-001-delegate-vtable-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-delegate-vtable-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.

The host-A (slot 0x48) excerpt was already exported byte-identical
by the RE-001-find-family-merge-115 (#3560) packet; the twin
(slot 0x58) excerpts by the RE-001-default-name-115 (#3563) packet;
and the delegate_impl excerpt by the RE-001-registry-find-115
(#3485) packet. This script regenerates them from the same binary
so the packet stays self-contained, and verify.py checks them
byte-for-byte against a fresh objdump run like every other excerpt.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    # Shared Customizable interface slots (Env vtable targets).
    ("slot10_get.txt", 0x609D760, 0x609D954),            # slot 0x10
    ("slot18_configure.txt", 0x609DC40, 0x609DE39),      # slot 0x18
    ("slot20_init.txt", 0x5D32560, 0x5D3257B),           # slot 0x20
    ("slot28_shared.txt", 0x6095E70, 0x609661C),         # slot 0x28
    ("slot30_shared.txt", 0x6096790, 0x6096F0C),         # slot 0x30
    ("slot38_shared.txt", 0x5D2E090, 0x5D2E0DE),         # slot 0x38
    ("slot40_status_stub.txt", 0x60956F0, 0x609570C),    # slot 0x40
    ("slot48_host_a.txt", 0x609D0E0, 0x609D75E),          # slot 0x48 (re-ship #3560)
    ("slot50_shared.txt", 0x60986B0, 0x6098A9C),         # slot 0x50
    ("slot58_shared.txt", 0x6095710, 0x609579A),         # slot 0x58
    ("slot60_shared.txt", 0x609DE80, 0x609E29E),         # slot 0x60
    ("slot68_shared.txt", 0x609D980, 0x609DC18),         # slot 0x68
    ("slot70_name_env.txt", 0x5FCC0D0, 0x5FCC0DC),       # slot 0x70 (Env "")
    ("slot78_name_string.txt", 0x5D32A30, 0x5D32A51),    # slot 0x78
    ("slot80_isinstance.txt", 0x5D2E770, 0x5D2E832),     # slot 0x80 canonical
    ("slot88_false.txt", 0x5D2CA00, 0x5D2CA07),          # slot 0x88 (Env 0)
    ("slot90_nickname_env.txt", 0x5D2CA10, 0x5D2CA1C),   # slot 0x90 (Env "")
    ("slot98_status_stub_env.txt", 0x5FCC0E0, 0x5FCC0FC),  # slot 0x98 (Env)
    # Per-class overrides of the identity / dispatch slots.
    ("slot98_unwrap.txt", 0x5D4D490, 0x5D4D552),         # slot 0x98 (SCW unwrap)
    ("stats_name.txt", 0x606FA20, 0x606FA2C),            # slot 0x70 (Stats)
    ("stats_slot88.txt", 0x606FA30, 0x606FA39),          # slot 0x88 (Stats)
    ("mockenv_slot80.txt", 0x5FD6240, 0x5FD6271),        # slot 0x80 (MockEnv)
    ("compenvwrap_name.txt", 0x5FD4E60, 0x5FD4E6C),      # slot 0x70 (CompEnvWrap)
    ("posixclock_name.txt", 0x5FE0FE0, 0x5FE0FEC),       # slot 0x70 (PosixClock)
    ("posixclock_nickname.txt", 0x5FE0FF0, 0x5FE0FFC),   # slot 0x90 (PosixClock)
    ("posixenv_name.txt", 0x5FE1000, 0x5FE100C),         # slot 0x70 (PosixEnv)
    ("posixenv_nickname.txt", 0x5FE1010, 0x5FE101C),     # slot 0x90 (PosixEnv)
    ("mockenv_name.txt", 0x6025790, 0x602579C),          # slot 0x70 (MockEnv)
    ("emulatedclock_name.txt", 0x60257A0, 0x60257AC),    # slot 0x70 (Emulated)
    ("scw_slot28.txt", 0x5FCF590, 0x5FCF658),            # slot 0x28 (SCW)
    ("scw_slot60.txt", 0x5FCDAE0, 0x5FCDF63),            # slot 0x60 (SCW)
    ("slot98_shared.txt", 0x5FD5A00, 0x5FD5A73),         # slot 0x98 (Comp/Posix/Mock)
    ("stats_slot98.txt", 0x6070490, 0x60704D2),          # slot 0x98 (StatisticsImpl)
    ("posixclock_slot98.txt", 0x5FE1540, 0x5FE1589),     # slot 0x98 (PosixClock)
    ("emulatedclock_slot98.txt", 0x60259E0, 0x6025A08),  # slot 0x98 (EmulatedClock)
    ("slot38_resolver.txt", 0x60958C0, 0x6095A57),       # slot 0x38 resolver (shared)
    ("conf_slot38_db.txt", 0x60A0240, 0x60A029B),        # slot 0x38 (DBOptions)
    ("mockenv_slot28.txt", 0x5FD7560, 0x5FD76B1),        # slot 0x28 (MockEnv)
    ("mockenv_slot60.txt", 0x5FD5E00, 0x5FD5F07),        # slot 0x60 (MockEnv)
    ("mockenv_slot88.txt", 0x5FD4E70, 0x5FD4E79),        # slot 0x88 (MockEnv)
    ("scw_slot88.txt", 0x5FCC3F0, 0x5FCC3F9),            # slot 0x88 (SCW)
    ("zero_stub_copy.txt", 0x5FCC100, 0x5FCC11C),        # zero-stub copy
    # Configurable-family representatives (14-slot vtables).
    ("conf_slot10.txt", 0x6099030, 0x60990CC),           # slot 0x10 (Configurable)
    ("conf_slot18.txt", 0x60996A0, 0x60996DE),           # slot 0x18 (Configurable)
    ("conf_slot38.txt", 0x607DD50, 0x607DDAB),           # slot 0x38 (CFOptions)
    ("conf_slot48_mut.txt", 0x607E420, 0x607E536),       # slot 0x48 (MutCFOptions)
    ("conf_slot48_db.txt", 0x60A2470, 0x60A3191),        # slot 0x48 (DBOptions)
    ("twin_a.txt", 0x6086B70, 0x6086CC9),                # slot 0x58 (re-ship #3563)
    ("twin_b.txt", 0x60A7420, 0x60A7579),                # slot 0x58 (re-ship #3563)
    ("conf_slot60.txt", 0x60985E0, 0x609865E),           # slot 0x60 (Configurable)
    ("conf_slot68.txt", 0x6095A60, 0x6095B14),           # slot 0x68 (Configurable)
    # Logger-family representatives (11-slot vtables).
    ("logger_slot10.txt", 0x5FCC410, 0x5FCC473),         # slot 0x10 (Logger)
    ("testmem_slot30.txt", 0x6025980, 0x6025989),        # slot 0x30 (TestMemLogger)
    ("testmem_slot50.txt", 0x5FCC480, 0x5FCC49C),        # slot 0x50 (TestMemLogger)
    # The dispatch call site: delegate_impl calls slot 0x48.
    ("delegate_impl.txt", 0x6097110, 0x609714E),         # re-ship #3485
]


def main():
    (PACKET / "excerpts").mkdir(exist_ok=True)
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / "excerpts" / name).write_text(text)
        print("wrote excerpts/%s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
