#!/usr/bin/env python3
"""Regenerate every disassembly excerpt in this packet, byte-for-byte.

Each excerpt is one whole function (FDE range from readelf
--debug-dump=frames-interp), emitted by
``objdump -d --start-address=<start> --stop-address=<stop>
work/hl-node-115.bin`` run from the repo root.  The objdump command
is recorded in the work-item README, and the excerpts are the raw
objdump text exactly as emitted: instruction mnemonics such as
``endbr64`` are genuine instructions present in the target binary,
not placeholders.

Ten excerpts (EnvLogger LogHeader, leveled Logv, Logv core,
GetInfoLogLevel, SetInfoLogLevel, Close, CloseImpl, Logv, and
AutoRollLogger LogHeader and GetInfoLogLevel) are re-shipped
byte-identical from PR #4315's packet
(research/work-items/RE-001-dump-slot-method-names-115/), with credit
in the README; they regenerate to the same bytes from the same binary.

Usage: python3 export_excerpts.py  (run from the repo root)
"""

import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent
BIN = "work/hl-node-115.bin"

# (file name, start, stop) -- whole functions only.
EXCERPTS = [
    # EnvLogger slots (re-shipped from #4315).
    ("logger-logheader-5fcc200.objdump.txt", 0x5FCC200, 0x5FCC218),
    ("logger-logv-levelled-5fcd400.objdump.txt", 0x5FCD400, 0x5FCD419),
    ("logger-logv-levelled-core-5fcd2c0.objdump.txt", 0x5FCD2C0, 0x5FCD3F5),
    ("logger-getinfologlevel-5fcc220.objdump.txt", 0x5FCC220, 0x5FCC229),
    ("logger-setinfologlevel-5fcc230.objdump.txt", 0x5FCC230, 0x5FCC239),
    ("logger-close-5fcc410.objdump.txt", 0x5FCC410, 0x5FCC473),
    ("logger-closeimpl-5fceae0.objdump.txt", 0x5FCEAE0, 0x5FCEB1F),
    ("logger-logv-5fce280.objdump.txt", 0x5FCE280, 0x5FCE766),
    # EnvLogger slots completed by this packet.
    ("logger-d0-5fcfb90.objdump.txt", 0x5FCFB90, 0x5FCFDDF),
    ("logger-d1-5fcfde0.objdump.txt", 0x5FCFDE0, 0x5FD003F),
    ("logger-getlogfilesize-5fcced0.objdump.txt", 0x5FCCED0, 0x5FCCF05),
    ("logger-flush-5fce130.objdump.txt", 0x5FCE130, 0x5FCE27D),
    ("logger-closeimpl-worker-5fce770.objdump.txt", 0x5FCE770, 0x5FCEADD),
    # AutoRollLogger slots (LogHeader / GetInfoLogLevel re-shipped).
    ("autoroll-logheader-6057000.objdump.txt", 0x6057000, 0x60571B4),
    ("autoroll-getinfologlevel-60552e0.objdump.txt", 0x60552E0, 0x6055345),
    ("autoroll-d0-60576b0.objdump.txt", 0x60576B0, 0x6057CF1),
    ("autoroll-d1-6057d00.objdump.txt", 0x6057D00, 0x6057D1B),
    ("autoroll-logv-6058770.objdump.txt", 0x6058770, 0x6058A60),
    ("autoroll-getlogfilesize-6057590.objdump.txt", 0x6057590, 0x60576B0),
    ("autoroll-flush-6057440.objdump.txt", 0x6057440, 0x605758E),
    ("autoroll-setinfologlevel-6055280.objdump.txt", 0x6055280, 0x60552D8),
    ("autoroll-closeimpl-60551d0.objdump.txt", 0x60551D0, 0x605523B),
    # Perf-context / TLS helpers used by Logv and Flush.
    ("helper-get-perf-level-606ddd0.objdump.txt", 0x606DDD0, 0x606DDF0),
    ("helper-set-perf-level-606ddb0.objdump.txt", 0x606DDB0, 0x606DDCB),
    ("helper-tls-init-606d9f0.objdump.txt", 0x606D9F0, 0x606DA30),
    ("helper-mutex-destroy-60d5170.objdump.txt", 0x60D5170, 0x60D5200),
    ("helper-mutex-lock-60d5230.objdump.txt", 0x60D5230, 0x60D52C5),
    ("helper-mutex-unlock-60d52f0.objdump.txt", 0x60D52F0, 0x60D5385),
    ("helper-mutex-noop-60d5390.objdump.txt", 0x60D5390, 0x60D5395),
    # The WritableFileWriter methods the Logger slots call.
    ("writer-append-6054680.objdump.txt", 0x6054680, 0x605518B),
    ("writer-flush-6051a20.objdump.txt", 0x6051A20, 0x605257C),
    ("writer-close-6052b80.objdump.txt", 0x6052B80, 0x6054600),
    # Construction / destruction.
    ("logger-sharedptr-dispose-5fcf660.objdump.txt", 0x5FCF660, 0x5FCF88C),
    ("logger-factory-5fd0de0.objdump.txt", 0x5FD0DE0, 0x5FD176A),
    ("autoroll-ctor-605a210.objdump.txt", 0x605A210, 0x605AE90),
    # The rollover path (AutoRollLogger Logv callees).
    ("autoroll-roll-6058110.objdump.txt", 0x6058110, 0x60586F3),
    ("autoroll-timecheck-6057310.objdump.txt", 0x6057310, 0x605743C),
    ("autoroll-relog-60572a0.objdump.txt", 0x60572A0, 0x6057304),
    ("autoroll-mkname-6056790.objdump.txt", 0x6056790, 0x6056B94),
    ("autoroll-mkname2-6056ba0.objdump.txt", 0x6056BA0, 0x6056E42),
    ("autoroll-format-6056e50.objdump.txt", 0x6056E50, 0x6056FC3),
]


def main():
    (HERE / "excerpts").mkdir(exist_ok=True)
    for name, start, stop in EXCERPTS:
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        (HERE / "excerpts" / name).write_text(out)
    print(f"wrote {len(EXCERPTS)} excerpts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
