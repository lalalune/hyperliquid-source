# Collection and build commands

Working directory: repository root. Only new Rust executes. The pinned captured
artifact is parsed/disassembled, never run or instruction-emulated.

```sh
git fetch origin main
git switch -c research/node94-indexed-qword-swap-rust origin/main
python3 -O research/work-items/RE-001-indexed-qword-swap-rust-94/static_evidence.py --out research/work-items/RE-001-indexed-qword-swap-rust-94/static
python3 -O research/work-items/RE-001-indexed-qword-swap-rust-94/oracle.py --freeze
```

Freeze succeeded before any new component source existed. Source was authored
and rustfmt applied afterwards. Complete static exports use GNU and LLVM:

```
objdump -d --start-address=0x4fa90a0 --stop-address=0x4fa9109 artifacts/node/94/hl-node
objdump -d --start-address=0x4fabb90 --stop-address=0x4fac29f artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node
```

GNU is `/opt/homebrew/opt/binutils/bin/objdump`; LLVM is `/usr/bin/objdump`.
Exact tool versions are retained. Full frame output is read incrementally,
keeping complete bound FDE/CIE records. Nearest-symbol labels are not used to
infer source identity.

The first native attempt stopped on an unused argument warning in a wrong-source
control. Its compiler output and failed control source are retained under logs;
no initial partial result is qualification evidence. Correcting that control and
its analogous table-argument control changed neither product source nor oracle.
The entire verifier was rerun in a fresh directory:

```sh
python3 -O research/work-items/RE-001-indexed-qword-swap-rust-94/verify.py --out work/indexed-qword-swap/native-final-2
```

`native/commands.json` records every final compiler argv/cwd/exit/output. Flags
pin Rust 1.94.1, edition 2024, opt0/opt3, one codegen unit, checked overflow,
abort panic, no debuginfo, warnings denied and a stable remapped build directory.
Both library and input-only client are built twice at each optimization level.
The client receives only frozen input rows on stdin. Every mutant must compile,
exit normally and differ from the same frozen expected rows.

Raw stdout is retained in one deterministic gzip JSON using a shared dictionary
of complete lines and per-stream indices. Each stream retains its original
label, byte count and SHA-256; joining the indexed lines recovers exact bytes
including newlines. No comparisons, fields or output values are discarded.
Global/focused commands are in README with raw logs. No full-suite, hosted CI,
container, original binary match or progress-gate result is claimed.
