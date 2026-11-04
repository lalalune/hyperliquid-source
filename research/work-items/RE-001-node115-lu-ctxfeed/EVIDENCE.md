# RE-001-node115-lu-ctxfeed: the node #115 lu ctx feeder

- Component ID: RE-001-node115-lu-ctxfeed
- Target release and full SHA-256: node #115, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis)
- Claim status: observation for all byte-level claims below; inference
  for the "generation" and "freshness" glosses, which are named as such;
  unresolved for the helper internals listed in README
- Scope included and excluded: included — the complete FDE
  `0x63e9cd0..0x63ead50` (4,224 bytes), its 50 outgoing direct calls,
  its 55 incoming direct callers, and the arg tuples at the three
  `0x6363660` sites. Excluded — internals of every callee, the
  second argument's pointee, and the per-index struct fields other
  than `+0x10`; earlier packets' bytes, cited by address only.

## Reproduce

Working directory: repository root (worktree
`~/workspace/hl-wt-calls221-115`). Tools: GNU objdump/readelf
(binutils, as installed), Python 3.12. No execution of the node binary
at any point; all reads are static byte reads and disassembly.

```sh
objdump -d --start-address=0x63e9cd0 --stop-address=0x63ead50 artifacts/node/115/hl-node
python3 tools/node115_lu_ctxfeed.py
python3 -m unittest tests.test_node115_lu_ctxfeed -v
make doctor verify catalogue-check test
(cd research/work-items/RE-001-node115-lu-ctxfeed && sha256sum -c MANIFEST.sha256)
```

Coordinate system: `.text` file offset = VA − 0x1000;
`.data.rel.ro`/`.got` = VA − 0x2000; `.rodata` = VA as-is. RELATIVE
`.got` slots are zero-filled in the file, so the GOT census uses
`.rela.dyn` addends (60,723 entries).

## Evidence

Boundaries, validated: entry `endbr64` at `0x63e9cd0`; next `endbr64`
at `0x63ead50`; `int3` padding `0x63ead4c..0x63ead50`; single `ret`
at `0x63e9d5a` (shared epilogue via `0x63e9d39` stack check).
Raw disassembly of the full FDE was read end to end (1,249 objdump
lines for the `0x63e9cd0..0x63eb200` window, of which this FDE is the
first 4,224 bytes); the five exhibits beside this record pin the
entry, the gate, the generation dispatch, and two of the three feed
sites. The third feed site (`0x63ea495`) has the identical arg tuple
and is verified by the verifier's call-target check, not by an
exhibit.

Key bytes, all confirmed against the binary:

- Entry: `f3 0f 1e fa` at `0x63e9cd0`, pushes, `sub $0xd8, %rsp`.
- Gate: `movzwl 0x14(%rdx)`, `movzwl 0x12(%rdx)`, `sub %ecx, %ebx`,
  table load from `0x6728868`, `lea (%rbx,%rdx,8)`, `shr $0x3,
  %r10w`, `jne 0x63e9d60` (`75 27` at `0x63e9d37`).
- Generation dispatch (`0x63ea0e5` exhibit): `shr $0x1c, %rdi`,
  `and $0x3ff, %edi`, `cmp %edi, 0x10(%rsi)`, `je` collect,
  `cmp $0x1, %edi`, `jne` drop.
- Feed sites: `e8 26 95 f7 ff` at `0x63ea135`,
  `e8 c6 91 f7 ff` at `0x63ea495`, `e8 88 8b f7 ff` at `0x63eaad3`,
  each resolving by rel32 to `0x6363660`; arg setup immediately
  before each is (rdi = `-0x58(%rbp)`, rsi = `-0x68(%rbp)`,
  rcx = `r14`), with rdx carrying the scanned item.
- Collect sites: `e8 bd 89 f7 ff` at `0x63eab9e`,
  `e8 4a 89 f7 ff` at `0x63eac11`, `e8 62 88 f7 ff` at `0x63eacf9`,
  each resolving to `0x6363560`, followed in each case by an append
  to the `-0xc0(%rbp)` array with the count at `-0x70(%rbp)`.
- Obj gate: `cmp %ebx, 0x13450(%rsi)` at `0x63ea4c9` against the
  `.bss` word at `0x650969c`, `jb 0x63ea4e4` skipping the obj
  unlock (`+0x2968` mutex, `+0x2990` flag byte).
- Shard derivation: `shr $0x26` / `and $0x3f` shard index,
  `table32[0x6511780 + index*4]`, `+ obj-value + shard*224`
  (`lea`/`shl $0x5` sequence at `0x63e9f52..0x63e9f64`),
  `pthread_mutex_trylock` on object `+0x40` at `0x63e9f72`.
- Head comparison: `cmp 0xc0(%r14), %rdx` at `0x63ea101`,
  `0x63ea461`, and `0x63eaaa6` — one per feed site.
- Exit: final sweep calls `0x63612b0` at 7 sites with (ctx, table
  value, item); obj field rewrite at `0x63ea994..0x63ea9b4`
  (`[obj+0x12] = (u16)([obj] + (u16)([obj+0x14] - [obj]) -
  table16*8)`).

Callers/callees: 56 direct E8 callers of `0x63e9cd0` across `.text`
(each confirmed by objdump, not just byte scan), 0 GOT references.
Outgoing: 50 direct E8, 39 `jmp` lines all targeting inside the FDE,
1 `ret`. No indirect call, LEA-to-code, or GOT use is claimed for
this FDE beyond the tables named above (`.bss` tables at `0x6728868`,
`0x6727a00`, `0x65096c0`, `0x6511780`, `0x6511820`, `.bss` word
`0x650969c`, global `0x64ee138`).

## Implementation and comparison

Not yet implemented/measured: no Rust reconstruction is attempted in
this packet. The verifier and unit tests below check the static
claims only (bytes, counts, census, manifest), not behaviour.

## Results and limitations

- Verifier: exit 0 (5 excerpts, 205 bytes, 46 strict mnemonics,
  outgoing 50 E8, incoming 56 E8, 0 GOT, MANIFEST 15/15).
- Unit tests: 9/9 (regeneration, key bytes, FDE bounds, manifest
  coverage, strict counts, tamper control, verifier exit zero, and
  the census spot checks).
- `make verify`: exit 0. `make catalogue-check`: exit 0.
  `make test`: 77 files attempted, 1 failed — the single failure is
  the pre-existing `test_node115_catalogue` Errno 18
  cross-device-link error, identical on pristine checkouts, not a
  packet regression; this packet's file passes 9/9.
- What remains unknown is listed under README "Unresolved". No gate
  is requested by this packet. Next question: decode the collect
  sibling `0x6363560` end to end — its (unused, obj, item, ctx)
  behaviour, how it differs from `0x6363660`'s head/slot/anchor
  state machine, and what consumes the output array this feeder
  appends to.
