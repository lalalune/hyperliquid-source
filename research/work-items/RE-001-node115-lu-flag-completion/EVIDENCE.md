# RE-001-node115-lu-flag-completion: what the flag helper selects, and what the completion helper does at count zero

- Component ID: RE-001-node115-lu-flag-completion
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only tree)
- Claim status: observation
- Scope included and excluded: see README.md Scope section. The two claimed FDEs are `0x4dccf20..0x4dcd300` (flag helper, 992 bytes) and `0x4da86a0..0x4da885b` (completion helper, 443 bytes). Characterization-only callees (`0x57fafd0` lookup, `0x4d35b60` resolver, `0x4d24790` leaf op, `0x5155ec0` grow, `0x5b99ef0`/`0x51e8720` drain, `0x58132d0` shift) are cited by address; their bytes are not claimed.

## Reproduce

Exact commands, working directory = worktree root:

```sh
objdump -d -M intel --start-address=0x4dccf20 --stop-address=0x4dcd300 artifacts/node/115/hl-node
objdump -d -M intel --start-address=0x4da86a0 --stop-address=0x4da885b artifacts/node/115/hl-node
readelf -r artifacts/node/115/hl-node
readelf --debug-dump=frames-interp artifacts/node/115/hl-node
python3 tools/node115_lu_flag_completion.py
python3 -m unittest tests.test_node115_lu_flag_completion -v
```

Tool versions: system `objdump`/`readelf` (binutils), `python3` stdlib only
for the verifier. No execution of the node binary; no side effects beyond
reading the binary and the packet files. Coordinate system: `.text` file
offset = VA − 0x1000; `.data.rel.ro`/`.got` file offset = VA − 0x2000;
`.rodata` file offset = VA.

## Evidence

Validated boundaries (via `.eh_frame`, `readelf --debug-dump=frames-interp`):

- Flag helper FDE `pc=0x4dccf20..0x4dcd300`, CIE `0039672c` (zPLR).
  Body proper to the single `ret` at `0x4dcd2c0` = 928 bytes / 234
  instructions; tail = 64 bytes / 17 instructions; total 251.
  Full-FDE SHA-256
  `1f553432dcdfc266e8c5199fffde1e93f78ef777daaa01ba4d827e211669be72`;
  body-proper SHA-256
  `0755b0a92a47356d34f74014b45b7ccef69e0b37df9b7bde7392112a23719091`.
- Completion helper FDE `pc=0x4da86a0..0x4da885b`, CIE `00000000`.
  Body proper to the single `ret` at `0x4da881b` = 379 bytes / 102
  instructions; tail = 64 bytes / 11 instructions; total 113.
  Full-FDE SHA-256
  `338fee89876ab02fa1f9ac5f2948c35cd8a6f64fbf3283ab16796d3de1376361`;
  body-proper SHA-256
  `7afb93c6e32ad71cc32050e9287bb0e466dcf2aea214832d6e974c4fd2761da3`.

Raw disassembly/data: `fdeccf20.hex` / `fdeccf20.objdump.txt` and
`fde86a0.hex` / `fde86a0.objdump.txt` beside this record; every
address in the README was checked against these dumps.

Callers/callees/indirect calls (whole-`.text` byte scans):

- Flag helper: direct `E8` callers `0x4fb530f` (bytes
  `e8 0c 7c e1 ff`) and `0x4fac740` (bytes `e8 db 07 e2 ff`); no
  `R_X86_64_RELATIVE` addend equals `0x4dccf20`, so 0 GOT sites.
- Completion helper: direct `E8` caller `0x4fb539e` (bytes
  `e8 fd 32 df ff`); no addend equals `0x4da86a0`, so 0 GOT sites.
- Lookup helper `0x57fafd0`: direct `E8` callers `0x4dcd06c`
  (the flag helper), `0x4fac5fa`, `0x4fac8d2`; 0 GOT sites.
- Completion GOT resolutions (via `readelf -r`): slot `0x64df4a0`
  `R_X86_64_RELATIVE` → `0x635de30` (free call, args
  `(ptr, 0x148, 0)`); slot `0x64df568` `R_X86_64_GLOB_DAT` →
  `memmove@GLIBC_2.2.5` (shift callee); slot `0x64df770`
  `R_X86_64_RELATIVE` → `0x1680bd0` (panic); slot `0x64df730`
  → `0x1680e60` (panic); slot `0x64df830` → `0x1680c10`
  (location-only panic).

Source mapping evidence (panic Locations, via relocation addends):

- `0x649cc20`: file addend `0x4402cd` = `base/src/l1_map/entry.rs`
  (24 bytes), line 210, col 39; message `occupied entry index`
  (20 bytes at `.rodata 0x9171b6`).
- `0x649a528`: file addend `0x4344f8` =
  `/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/alloc/src/collections/btree/node.rs`
  (91 bytes), line 618, col 9; message
  `assertion failed: self.height > 0` (33 bytes at `.rodata
  0x913418`).
- `0x64a36d0`: file addend `0x430444` =
  `/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/alloc/src/collections/btree/map/entry.rs`
  (96 bytes), line 614, col 42; location-only panic call, no
  message argument.

ABI/layout/overflow observations:

- Flag-helper out-struct: `{flag: u64, A, B, C, D}` (8 bytes each);
  caller compares the flag's low dword. Small hit: `(1, 0, table,
  key)`; small miss: `(0, 0, table, key, key)` with `D` written only
  on the absent path; tree hit: `(1, node, remaining, key-position,
  &table.buffer)`; tree miss: flag 0, trailing fields
  path-dependent.
- Table struct (32 bytes): `[0]` capacity, `[0x8]` buffer, `[0x10]`
  head/start, `[0x18]` length — inferred from the lookup's wrap
  arithmetic (`min(head, capacity)` split into two runs) and the
  flag helper's threshold (`<= 63` small, `> 63` grow) and reset
  (`[0] == INT64_MIN`, length `< 32`) checks.
- Node (328 bytes): 16-byte value slots at `+16*i`; u32 keys at
  `+0xb8 + 4*i` (bswapped compare); u16 counters at `+0xe4` and
  `+0xe6` (walk uses `+0xe6` as the key count; leaf op writes
  `+0xe4`); child pointers at `+0xe8 + 8*i`; parent at `+0xb0`.
  `0xb8 + 44 + 4 + 96 = 0x148` matches the free size.
- Completion entry (24 bytes): 16-byte value, flag byte at `+0x10`,
  dwords at `+0x11` and `+0x14` (overlapping by one byte; together
  with the flag byte they reproduce `+0x10..0x18` verbatim).
- Overflow/panic order: the table-path flag-byte-2 panic fires AFTER
  the memmove shift and the count decrement, not before.
- Analysis was complete for the two claimed FDEs (every instruction
  read) and partial for the characterization callees (entry/exit
  and flag-relevant paths only).

## Implementation and comparison

Not yet implemented/measured. No Rust reconstruction of either FDE is
claimed; no build, Cargo graph, or equivalence comparison is offered.
The packet is evidence only.

## Results and limitations

Machine-readable metrics: verifier exit 0 (binary digest/size, both
FDE byte sets and SHAs, ret bytes, 12 opcode spot checks, GOT
relocation addends, panic strings and Location addends, packet
hex/records agreement, whole-`.text` caller census re-derived by
byte scan); packet unit tests 7/7; MANIFEST 7/7 (packet files) plus
tools/tests entries; `make doctor` analysis_ready true; `make
verify` exit 0; `make catalogue-check` exit 0; full `make test`:
77 files attempted, 1 failed — the pre-existing
`test_node115_catalogue` Errno 18 failure only.

What remains unknown: see README.md Limitations (leaf-op flag
condition meaning, grow/drain internals, table field names, `+0xe4`
counter role, tree-miss trailing fields). No progress gate is
requested by this packet; it is a research evidence packet.

Next question: decode the leaf op `0x4d24790` end to end — what does
its `rax == 0` flag condition mean (which node state makes the
completion helper unlink and free), and what is the node `+0xe4`
second counter it writes? A second thread is the grow callee
`0x5155ec0`: what exactly does the array-to-tree conversion past
length 63 build?
