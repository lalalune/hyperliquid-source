# RE-001-node115-lu-classremove: class remove — unlink, merge, empty

- Component ID: RE-001-node115-lu-classremove
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`,
  105,896,032 bytes,
  SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `05bc2de30`
  (confirmed before analysis; unmoved during the build)
- Claim status: observation for all byte-level claims below;
  inference for the merge-loop invariant and the caller's
  domain role; unresolved for the items listed in the README
- Scope included and excluded: included is the single FDE
  `0x63b9d10..0x63ba5fd` (2285 bytes) and its single call
  site (cited). Excluded: the neighbour caller FDE's own
  logic (cited only, #242's question), the handoff/register/
  gate/driver FDEs (cited only), and any runtime `.bss`
  contents (not readable from the file).

## Reproduce

Working directory: a fresh worktree of lalalune/hyperliquid-source
at `05bc2de30`. Static analysis only; the binary was never
executed.

- `sha256sum artifacts/node/115/hl-node` →
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- `objdump -d --start-address=0x63b9d10 --stop-address=0x63ba5fd
  artifacts/node/115/hl-node` → 601 mnemonic lines, single
  `ret` at `0x63b9f79`, zero `call` lines.
- `readelf --debug-dump=frames-interp artifacts/node/115/hl-node`
  → FDE `pc=0x63b9d10..0x63ba5fd`.
- `python3 tools/node115_lu_classremove.py` → exit 0
  ("all checks passed").
- `python3 -m unittest tests.test_node115_lu_classremove` →
  10/10 pass.
- `make verify` → exit 0 (559 manifests, 7171 entries).
- `make catalogue-check` → exit 2, `Stale catalogue: README.md`
  (pre-existing on the new base; identically on a pristine
  `05bc2de30` checkout per packets #234–#240).
- Full `make test` was not attempted (584 files on the new
  base; hours-long and liable to VM-restart termination, as
  shown in #234). No suite tally is claimed.

## Evidence

Coordinate system: VA addresses as shown by objdump; `.text`
file offset = VA − 0x1000 (re-derived from program headers:
PT_LOAD off `0x1418300` ↔ vaddr `0x1419300`, as in #236);
`.rodata` = VA as-is; `.rela.dyn` addends used for the GOT
census (RELATIVE `.got` slots are zero-filled in the file).

Validated boundaries: FDE `0x63b9d10..0x63ba5fd` by
`.eh_frame`; `endbr64` at entry (`f3 0f 1e fa`); `int3`
padding `0x63b9d0c..0x63b9d10` (4 bytes) and
`0x63ba5fd..0x63ba600` (3 bytes, before the #236 consume
helper at `0x63ba600`); single `ret` at `0x63b9f79`
(`c3`); the `ret` sits mid-FDE and later blocks jump back
to the shared epilogue at `0x63b9f6f` (pops).

Raw disassembly/data: 6 exhibits beside this record
(`rm_entry`, `rm_head`, `rm_empty`, `rm_merge`, `rm_side`,
`rm_epi`), 259 bytes, 71 strict instructions (strict =
address + bytes field + tab + mnemonic; objdump
byte-continuation lines excluded). Key byte facts:

- Head dispatch: `cmp %rbx,%rsi; je 0x63b9fd0` at
  `0x63b9d25..0x63b9d2b` (`rbx = [entry]`, `rsi = block`).
- Count reset: `movq $0x0,0x8(%rdi)` at `0x63b9fe4`
  (`rdi = entry`, head-with-side-child path only).
- Emptying store: `mov %rdx,(%rdi)` at `0x63ba308`
  (`rdi = entry`, `rdx = [block+0x30]`); with `rdx == 0`
  this writes `0` into `[entry]`.
- Side promotion tail: `mov %rcx,(%r8)` at `0x63ba4d3`
  (`r8 = entry` on the head path, `rcx = side child or
  merged head`).
- Merge loop head (`rm_merge`): forward load, both keys
  (`[cur+8]`, `[next+8]`), sign via `setb`/`sbb`,
  conditional dispatch; rewire steps use the same 16-byte
  `movups` pair-store idiom as #239.
- Epilogue (`rm_epi`): parent-slot splice, pops, `ret`.

Callers/callees/indirect calls: zero calls inside the FDE;
one direct `E8` caller, site `0x63d870f` (neighbour FDE
`0x63d8630..0x63d8790`, confirmed by rel32), args
`(rdi = first-arg + 16*index, rsi = block)`; 0 `E9`, 0
`LEA`, 0 GOT (60,723 `.rela.dyn` entries, no addend hit).
All direct jump targets lie inside the FDE (whole-FDE
scan by the verifier).

Source mapping evidence: none claimed; this is a
binary-only decode. No implementation code is asserted
equivalent to the target.

Analysis completeness: the FDE was read in full (601
mnemonic lines). The head case is traced end to end; the
merge loop is characterized by its invariant (key-ordered
merge, same rewire idiom as #239) with swap forms verified
by the whole-FDE jump-target check rather than exhibited,
to keep the packet at 18 files — the same convention as
#239. No claim is made about a global sortedness proof
for merged chains or about exact per-merge step counts.

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is
included in this packet and no equivalence claim is made.
The packet is evidence only (README, records, exhibits,
static verifier, unit tests).

## Results and limitations

Machine-readable metrics: 6 exhibits, 259 bytes, 71
strict instructions; FDE 2285 bytes; census 1 E8 / 0 E9 /
0 LEA / 0 GOT; MANIFEST 17 entries; verifier exit 0;
unit tests 10/10; `make verify` exit 0 (559 manifests,
7171 entries); `make catalogue-check` exit 2
(pre-existing `Stale catalogue: README.md` failure, not a
packet regression); full `make test` not attempted.

What passed: all gates above. What remains unknown: the
exact per-merge step count and any global sortedness
guarantee; stale link words of the removed block on the
non-head path; the `[entry+8]` count word's domain
meaning; the neighbour caller FDE's domain role (#242's
question). The requested progress gate (verifier, unit
tests, MANIFEST, spot byte checks) covers the packet's
own scope; it does not cover the full test suite, and no
such coverage is claimed.

Next question (#242): decode the neighbour caller FDE
`0x63d8630..0x63d8790` end to end — its `+0x1080` queue
unlink, its size-class dispatch, and its
probe-then-bitmap-clear tail — and whether it is the
removal entry point for both queued and size-classified
blocks.
