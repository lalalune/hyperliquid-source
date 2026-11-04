# RE-001-node115-lu-completion-callers: completion-helper caller census and the acquire twin

- Component ID: RE-001-node115-lu-completion-callers
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes, `artifacts/node/115/hl-node`
- Source commit / reference commit: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only)
- Claim status: observation
- Scope included and excluded: see README.md Scope section

## Reproduce

Exact commands, tool versions, options, input and output hashes, working directory,
platform, environment requirements, and any declared execution/side effects.

Worktree base `8fd8db6`, verified unmoved by `git fetch` + `git rev-parse
origin/main` before analysis. Binary SHA-256 verified before every byte read.
`objdump` (GNU binutils, `-d -M intel`) over the two FDE ranges only; the
census scans read bytes with Python `struct`/`bytes.find` and `readelf -S/-r`.
No execution, no side effects: the node binary was never run.

```sh
objdump -d -M intel --start-address=0x4fac710 --stop-address=0x4fac7e0 \
  artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4da6c80 --stop-address=0x4da6d70 \
  artifacts/node/115/hl-node
python3 tools/node115_lu_completion_callers.py
python3 -m unittest tests.test_node115_lu_completion_callers -v
```

## Evidence

Original addresses and coordinate system (VA/file offset), validated boundaries,
raw disassembly/data, callers/callees/indirect calls, source mapping evidence,
ABI/layout/rounding/overflow observations. Keep raw files beside this record.
State whether analysis was complete, timed out or limited to a range.

Coordinate system: `.text` file offset = VA − 0x1000;
`.data.rel.ro`/`.got` file offset = VA − 0x2000; `.rodata` file offset = VA.
FDE boundaries come from the `.eh_frame_hdr` table (135,313 starts, sorted,
all inside `.text`): acquire `0x4fac710..0x4fac7e0`, cell resolver
`0x4da6c80..0x4da6d70`. Instruction counts are strict mnemonic-line counts
(address + byte field + tab + mnemonic); the one byte-continuation line at
`0x4da6d02` (`00 00`, tail of the `mov QWORD PTR [rsp+0x8],0x0` at
`0x4da6cfb`) is excluded — a loose regex gives 72 for the cell resolver,
the strict count is 71.

Census method (complete, whole binary, not a range): linear E8 and E9 scans
over all of `.text` resolving `rel32` targets; rip-relative LEA scan
(`48 8d` with modrm `mod=00, rm=101`) for address-taken sites; `.rela.dyn`
and `.rela.plt` addend scans; absolute 8-byte little-endian scans of
`.data.rel.ro`, `.rodata`, `.data`, `.got`, `.got.plt`,
`.gcc_except_table`, `.eh_frame`, `.eh_frame_hdr`. Results for the
completion helper `0x4da86a0`: E8 `[0x4fb539e]`, E9 `[]`, GOT `0`,
relocation addends `0`, LEA `0`, absolute data references `0`. Same method
for the cell resolver `0x4da6c80`: E8 `[0x4fac74a]` only. For the flag
helper `0x4dccf20`: E8 `[0x4fac740, 0x4fb530f]` only. For the resolver
`0x4d35b60`: E8 `[0x4da86c9]` only. For the delegates: `0x51f3e20`
E8 `[0x4da6cd6]` only; `0x57ec1b0` E8 `[0x4da6d12]` only.

GOT resolutions (via `readelf -r`, all `R_X86_64_RELATIVE`):
`0x64e0ff0` → `0x5bb2440` (timed wait, #190),
`0x64e1000` → `0x5bb35f0` (grant-wake, #193),
`0x64df770` → `0x1680bd0` (panic helper, shared by the acquire twin's
cell-resolver panic and gate-release's index panic),
`0x64df4c0` → `0x1680cab` (acquire unwind-path callee, identity open),
`0x64df4a0` → `0x635de30` (free, #195, cited for context only).

Source mapping evidence: the cell resolver's bounds panic and
gate-release's index panic share message VA `0x9171a2` ("Out of bounds
access", 20 bytes, `.rodata`), location struct VA `0x649cc08`
(`base/src/l1_map/entry.rs`, line 64, col 17; file string VA `0x4402cd`,
length 24; the file-pointer field reads 0 in the file and is supplied by
the `R_X86_64_RELATIVE` relocation addend `0x4402cd`), and GOT wrapper
`0x64df770`. The neighboring location struct `0x649cc20` (24 bytes later)
is the completion helper's "occupied entry index" panic (#195).

ABI/layout observations: acquire out struct `{P @+0, input dword @+0x8}`;
gate slot word at `P+0x10`, refcount at `P+0x0`; flag-out fields read by
the cell resolver at `@+0` (flag dword), `@+0x8` (node), `@+0x10`
(table), `@+0x18` (key/position), `@+0x20` (key dword), `@+0x24`
(trailing qword), `@+0x2c` (trailing dword); small-table entry stride 24
with the count at entry `+8`; tree value slots 16 bytes with the count at
slot `+0`. Overflow behavior: acquire's `lock inc [P]` followed by
`jle` → `ud2` guards against resurrecting a dead (non-positive)
refcount; the count cell itself is capped at 2 on the acquire path and
saturating-decremented on the release path (#194).

## Implementation and comparison

Independent Rust path, Cargo.lock, compiler/linker/build flags, two-build result,
raw and normalized comparisons and masks, helper/data/relocation closure,
fixture identities, boundary/error cases and corruption controls. Use "not yet
implemented/measured" where applicable, rather than implied success.

Not yet implemented/measured. This packet is observation only: no Rust
reconstruction is claimed. Corruption controls are the packet's own unit
tests (byte flip → verifier rejection, ret corruption → rejection, digest
mismatch → rejection).

## Results and limitations

Machine-readable metrics with explicit denominators, what passed/failed, what
remains unknown, and why any requested progress gate covers its entire scope.
If requesting no gate, say so. Finish with a concrete next question.

Metrics: acquire 208 bytes / 67 instructions (41 body + 26 tail);
cell resolver 240 bytes / 71 instructions (37 body + 34 tail);
completion census denominator = all of `.text` (83,719,936 bytes scanned)
plus all relocation tables and data sections listed above: 1 direct
caller, 0 every other mechanism. Unknown: internals of `0x51f3e20`,
`0x57ec1b0`, `0x1680cab`; callers of the acquire/release pair; runtime
behavior (none claimed). No gate is requested beyond the packet's own
verifier and unit tests plus the repository's `make verify`,
`make catalogue-check`, and `make test`.

Next question: census and decode the direct callers of the
acquire/release pair (`0x4fac710` / `0x4fb52e0`): which API operations
claim and release entries, and what do they do with acquire's NULL versus
`{P, input}` result?
