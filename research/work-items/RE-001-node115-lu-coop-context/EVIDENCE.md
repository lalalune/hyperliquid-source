# RE-001-node115-lu-coop-context: what the conversion's context pointer points to

- Component ID: RE-001, `base/src/lu.rs` conversion context pointer (Tokio coop path).
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: upstream main
  `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (node-115-only migration).
- Claim status: observation for the dereference chain, the coop callee's TLS
  and budget-cell branches, the proceed function's dedup-cache mechanism,
  and all census counts; inference for the "reentrancy guard" reading of the
  proceed `[rdi]` field (0 between calls, `-1` transient); unresolved for
  the Rust type identity of `P`/`Q`, the table's `+0x8` slot, the
  nonzero-guard-entry block composition, and the ultimate producer of `P`.
- Scope included and excluded: included — coop callee `0x5cf3b90..0x5cf3c32`
  (162B, 44 instructions) and proceed function `0x5cfc310..0x5cfc3d3`
  (195B, 58 instructions); the pass-through chain from the conversion's
  callers through the helper; GOT and Location resolutions; full census
  counts. Excluded — #183's conversion body and #184's helper body (cited,
  not re-claimed); the two proceed direct callers' bodies (context only);
  the indirect consumers of the `0x64014c0`/`0x6401300` slots.

## Reproduce

Working directory: the repository worktree at the base commit above.
Inputs: `artifacts/node/115/hl-node` (digest above). Tools: GNU objdump
(`objdump -d -M intel --start-address=.. --stop-address=..`), readelf
(`--debug-dump=frames-interp` for FDE ranges), Python 3 with `struct`/`re`
for the relocation and census scans. No execution of the node binary, no
network, no disassembler database: all analysis is static byte and
disassembly reading. Deterministic: the verifier
`tools/node115_lu_coop_context.py` re-checks the digest, both body hashes,
key byte patterns, all 6 GOT resolutions, all 3 Location records, and all
census counts, and exits 0. Declared side effects: none (read-only).

## Evidence

Original addresses are ELF virtual addresses (PIE). `.text` file offset =
VA − 0x1000; `.data.rel.ro`/`.got` file offset = VA − 0x2000; `.rodata`
file offset = VA. Validated boundaries: coop FDE `.eh_frame` offset
`0x33fef8`, length `0x34`, CIE `0x00000000`, range `0x5cf3b90..0x5cf3c32`
(ends at `int3` padding); proceed FDE `.eh_frame` offset `0x72ed08`,
length `0x3c`, CIE `0x39672c`, range `0x5cfc310..0x5cfc3d3` (main `ret` at
`0x5cfc3a5`, landing pad `0x5cfc3a6..0x5cfc3d3`). Raw disassembly and
bytes are beside this record (`coop.objdump.txt`, `coop.hex`,
`proceed.objdump.txt`, `proceed.hex`); structured records (FDEs, GOT,
Locations, census, chain) are in `records.json`. Callers/callees/indirect
calls: coop callee 52 indirect GOT sites / 0 direct; proceed 2 direct E8
callers + 1 tail jump; state machine and caller-2 0 direct / 0 `lea` / 1
relocated-data reference each. Source mapping evidence: the three Tokio
Location records resolved through RELATIVE addends (file slots zero).
ABI/layout observations: `Q = (table, payload)` with callable table slots
`+0x0` and `+0x10`; proceed Vec-like `(guard, capacity, buffer, length)`
with 16-byte entries; TLS state byte `fs:[-0xe8]`, flag byte `fs:[-0xea]`,
budget cell `fs:[-0x108]`, helper word `fs:[-0xec]`. Analysis was complete
over the two claimed FDEs and the census scans; it was not a whole-binary
disassembly. The two proceed direct callers and the slot consumers were
deliberately not decoded (out of scope).

## Implementation and comparison

Not yet implemented/measured: no Rust reimplementation is claimed, no
byte-window comparison is made, and no helper/data/relocation closure beyond
the 6 GOT slots and 3 Location records above is asserted. Boundary/error
cases covered by the verifier and unit tests: body-hash corruption, GOT
addend corruption (via the pinned expectations), census-count corruption
(52/2/0/0/0), and Location field corruption — each must fail the verifier.
The unit tests mutate packet files in place with restore-on-finish and
never execute the node.

## Results and limitations

Metrics with explicit denominators: coop body 162/162 bytes hash-pinned;
proceed body 195/195 bytes hash-pinned; GOT resolutions 6/6; Location
records 3/3; coop GOT census 52 sites in 45 FDEs, all 52 confirmed by
per-FDE objdump; proceed E8 census 2/2 confirmed by objdump; zero-count
censuses (coop/state-machine/caller-2 direct E8) 0 each by full `.text`
byte scan. `tools/node115_lu_coop_context.py` exits 0;
`tests/test_node115_lu_coop_context.py` passes (see test run).
What remains unknown: the Rust identities, the table `+0x8` slot, the
nonzero-guard-entry block composition, and the ultimate producer of `P`
(above). No progress gate is requested: this packet covers a bounded
follow-up question, not a full component scope. Next question: what the
table's slot `+0x8` does, and which code consumes the two
function-pointer slots to reach the state machine and caller-2 indirectly.
