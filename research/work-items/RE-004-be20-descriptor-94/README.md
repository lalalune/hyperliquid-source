# RE-004 be20 descriptor — node #94

## Claim status

**Claimed.** #172 listed the `0x574be20` object and its 6
neighborhood references without tracing them. This packet
resolves the descriptor's head record, its four-pair builder,
its two install sites, and all 8 neighborhood lea sites in
the `0x4e77xxx` FDEs:

- **The head record is six slots.** At `0x574be20`, six
  RELATIVE relocations resolve to: a 30-byte twin-shape
  constructor (`0x4e78670`) that installs `0x574be20`
  itself; two clone helpers (`0x1510490`, 105 B;
  `0x15103f0`, 153 B) that allocate, memcpy, and fill an
  out struct; a 3-byte zero stub (`0x4e78690`:
  `xor eax,eax; ret`); a 1-byte ret stub (`0x4e78660`);
  and a source-file string (revm-primitives `env.rs`).
  The constructor and both stubs are exclusive to this
  descriptor (1 relocation each); the clones (65 each)
  and the string (12) are shared with other records.
- **The four-pair builder.** FDE `0x4e77920..0x4e77ad6`
  (438 B) allocates four `{1,1}` cells and builds a
  64-byte out struct of (cell, descriptor-field-address)
  pairs: `(cell, 0x574be78)`, `(cell, 0x574bea8)`,
  `(cell, 0x574bed8)`, `(cell, 0x574bf08)`. The pair
  fields' file values are all 0 — the builder stores
  their addresses, never their contents.
- **The neighborhood uses.** Eight lea sites in three
  `0x4e77xxx` FDEs: the builder's five (four pair fields
  plus a reuse of `0x574be78`); a panic-wrapper call
  passing the `0x574be60` field address (journaled_state
  string slot) with the 43-byte unwrap-None message,
  reached only when `[r15+0x28]` is 0; a second
  panic-wrapper call passing the `0x574be48` field
  address (env.rs string slot) with the 67-byte overflow
  message slice; and an adjacent call passing the
  `0x574bf38` field address (pre_execution string slot)
  together with the 15-byte "already checked" literal.
- **No direct dispatch.** A full `.text` scan finds zero
  E8 calls and zero E9 jumps to any of the five code
  slots. The descriptor is the only route to them.

**Not claimed.** No defect, exploitability, or security
severity is claimed. The descriptor's identity (what type
or component it describes) is not identified — only its
fields, builders, and uses are. The numeric fields
(`99`, `0x900000281`, `100`, `0x1200000269`) are
reported as raw values, not interpreted. Descriptor
fields beyond `+0x118` and the intermediate
function-pointer fields (`+0x70..+0x110`) are not traced.

## Scope

Included:

- The descriptor head `0x574be20..0x574be78`: 6 slots
  (`slots.tsv`), numeric fields `+0x30` (99),
  `+0x38` (`0x900000281`), `+0x48` (100), `+0x50`
  (`0x1200000269`), and the second string field
  `+0x40` (journaled_state string, reloc entry 61874).
- The four-pair builder FDE `0x4e77920..0x4e77ad6`
  (438 B) with its 4 pairs (`builder.tsv`).
- The two install sites: the setter's self-install lea
  (`0x4e78683`, anchor) and the store FDE's
  `[rdx] = 0x574be20` store (`0x4e76a70`, anchor),
  both #172's claims re-cited. The store FDE
  (`0x4e76900..0x4e76af5`, 501 B) also writes
  `[rdx+0x8] = 0x1e629b`, which points at a NUL byte
  (empty string as a C string).
- The 8 neighborhood uses (`uses.tsv`) in FDEs
  `0x4e77060..0x4e7738c` (812 B),
  `0x4e77920..0x4e77ad6` (438 B), and
  `0x4e77ae0..0x4e77e8f` (943 B).
- 16 byte segments in `segments.txt` (14 claim,
  423 bytes; 2 anchors, 26 bytes, #172's claims
  re-cited with attribution, anchor digests matching
  #172's exactly).

Excluded:

- Descriptor fields beyond `+0x118` (further leas at
  `0x574bf50` and past exist and are not traced) and
  the intermediate function-pointer fields between
  `+0x70` and `+0x110` (relocations to small FDEs in
  the `0x4e76xxx` range, not analyzed).
- The internals of the panic-wrapper callees
  (`0x157a9f0`, `0x157b4a0`, `0x157a9b0`) beyond
  their wrapper heads (format string, length, and
  argument passing); the internals of the abort
  helper `0x1346068` beyond its 21-byte shape; the
  rest of the store FDE's struct construction beyond
  the two stores reported here.
- The #157–#176 subjects and #1543's fixed-eight topic.

## Observations

### The six slots

| slot | offset | reloc entry | target | shape |
|---|---|---|---|---|
| 0 | `+0x00` | 61868 | `0x4e78670` | 30 B ctor, twin shape, installs `0x574be20` |
| 1 | `+0x08` | 61869 | `0x1510490` | 105 B clone, free-gate + alloc + memcpy |
| 2 | `+0x10` | 61870 | `0x15103f0` | 153 B clone-cap, alloc + memcpy + size-class |
| 3 | `+0x18` | 61871 | `0x4e78690` | 3 B zero stub, `xor eax,eax; ret` |
| 4 | `+0x20` | 61872 | `0x4e78660` | 1 B ret stub |
| 5 | `+0x28` | 61873 | `0x1ea965` | revm-primitives `env.rs` path string |

The constructor (`0x4e78670..0x4e7868e`) is the twin
shape from #176: `mov rax,rdi; mov [rdi+0x8],rdx;
mov [rdi+0x10],rcx; mov [rdi+0x18],0;
lea rcx,[0x574be20]; mov [rdi],rcx; ret`. Its head
(19 B, `0x4e78670..0x4e78683`) is claimed here; its
tail (11 B, the self-install lea plus store plus ret)
is #172's `elem11-setter` segment, re-cited as anchor.

Clone `0x1510490` (105 B): if `rcx < 0`, calls GOT
`0x576dfb8` (RELATIVE-resolved to `0x1346068`, a
21-byte abort helper) with `(edi=0, rsi=len)`;
otherwise allocates via GOT `0x576dfd8`
(`0x54c06b0`), memcpys via GOT `0x576dfe0`
(`memcpy`), and writes `[out] = len, [out+0x8] =
alloc, [out+0x10] = len`. On alloc failure it calls
the same abort helper with `(edi=1, rsi=len)`.

Clone-cap `0x15103f0` (153 B): if `rcx == 0` uses
`1` as the allocation size, else allocates via GOT
`0x576dfd8`; memcpys via GOT `0x576dfe0`; writes
`[out] = alloc, [out+0x8] = len, [out+0x10] = len,
[out+0x18] = size-class`, where the size-class is
`4 * clamp(bsr-derived, 7) + 1` computed from the
length. On alloc failure it calls the abort helper
with `(edi=1, rsi=len)`.

Sharing: the constructor, ret stub, and zero stub
have exactly 1 relocation each (this descriptor
only). The two clones have 65 relocations each and
the env.rs string has 12 — the same (clone, clone)
pair and the same string recur in other records, so
they are shared helpers, not descriptor-private code.

### The numeric fields

`[0x574be50]` (`+0x30`) = 99, `[0x574be58]`
(`+0x38`) = `0x900000281` (low 32 = 641, high 32 =
9), `[0x574be68]` (`+0x48`) = 100, `[0x574be70]`
(`+0x50`) = `0x1200000269` (low 32 = 617, high 32 =
18). The second string field `[0x574be60]`
(`+0x40`) resolves by reloc entry 61874 to
`0x1e3a8c`, the revm-19.2.0 `journaled_state.rs`
path string. These values are reported raw; no
line/column or version interpretation is claimed.

### The four-pair builder

FDE `0x4e77920..0x4e77ad6` (438 B) takes `rdi` as
the out pointer (`rbx`) and builds a 64-byte struct:

| pair | cell | field address | cell out | field out |
|---|---|---|---|---|
| 1 | `{1,1}` alloc | `0x574be78` | `[rbx+0x00]` | `[rbx+0x08]` |
| 2 | `{1,1}` alloc | `0x574bea8` | `[rbx+0x10]` | `[rbx+0x18]` |
| 3 | `{1,1}` alloc | `0x574bed8` | `[rbx+0x20]` | `[rbx+0x28]` |
| 4 | `{1,1}` alloc | `0x574bf08` | `[rbx+0x30]` | `[rbx+0x38]` |

Each cell is a 16-byte allocation via GOT
`0x576dfd8` initialized to `{1, 1}`; each field
address comes from a lea (the first three leas are
claimed as segments; the fourth lea and the second
`0x574be78` lea sit inside the 45-byte pair-stores
segment). On alloc failure the builder calls GOT
`0x576e020` and hits `ud2`; its landing pad
decrements the saved cells' refcounts and calls drop
helpers. The builder returns `rbx`.

### The install sites (anchors)

- Setter: `0x4e78683` (`lea rcx,[0x574be20]`) is
  the constructor's own self-install; #172's
  `elem11-setter` segment (`0x4e78683..0x4e7868e`,
  11 B) is re-cited as anchor with matching digest.
- Store: FDE `0x4e76900..0x4e76af5` (501 B) saves
  `rdi` to `[rsp+0x20]`, then at `0x4e76a70` does
  `lea rcx,[0x574be20]; mov rdx,[rsp+0x20];
  mov [rdx],rcx; mov [rdx+0x8],0x1e629b` — i.e.
  `[out] = descriptor, [out+0x8] = 0x1e629b`.
  #172's `elem11-store` segment
  (`0x4e76a70..0x4e76a7f`, 15 B) is re-cited as
  anchor with matching digest. The byte at
  `0x1e629b` is `0x00` (empty string as a C string);
  it sits just past the chrono `mod.rs` path string.

### The neighborhood uses

- `0x4e772fb` (FDE `0x4e77060..0x4e7738c`):
  `lea rdi,[0x574be60]; call [GOT 0x576e470]` →
  `0x157a9f0`, a panic wrapper whose head loads the
  43-byte message "called `Option::unwrap()` on a
  `None` value" and passes the field address as the
  third argument. Reached only when `[r15+0x28]`
  is 0 (`test rcx,rcx; jne` back).
- `0x4e77e82` (FDE `0x4e77ae0..0x4e77e8f`):
  `lea rdi,[0x574be48]; call [GOT 0x576e1b0]` →
  `0x157b4a0`, a panic wrapper whose head loads the
  67-byte overflow-message slice ("attempt to
  multiply with overflow" + "attempt to negate with
  overflow" + "att") and passes the field address.
- `0x4e77e70` (same FDE): `lea rdx,[0x574bf38];
  mov esi,0xf; call [GOT 0x576e468]` → `0x157a9b0`
  with `rdi = 0x7c3620`, the 15-byte "already
  checked" literal. The `0x574bf38` field resolves
  by reloc entry 61887 to `0x1e3ec3`, the
  revm-19.2.0 `pre_execution.rs` path string.
- The builder's five leas are listed in the builder
  section above.

### No direct dispatch

A byte-level scan of all of `.text` finds zero E8
call sites and zero E9 jump sites targeting any of
the five code slots (`0x4e78670`, `0x1510490`,
`0x15103f0`, `0x4e78660`, `0x4e78690`). The
descriptor's relocation slots are the only
recorded route to them. (The clones' 65 relocations
each are other records' slots, not code references.)

## Inferences (separated from observations)

- The descriptor is a per-record header of function
  slots plus source-file strings, consumed by
  address (builders pair cells with field addresses;
  panic wrappers take field addresses as arguments)
  rather than by content: the pair fields' contents
  are 0, and the builder never dereferences them.
- The shared clones and the shared env.rs string
  show this record belongs to a family of records
  with the same shape; the exclusive constructor and
  stubs are what make this record this record.
- The "already checked" + pre_execution-field call
  and the two panic-wrapper calls suggest the
  descriptor's fields serve as diagnostic identities
  (which record, which file), but that reading is
  inference from call shapes only, not a proven
  framework identification.

## Limitations

- The "no direct call" census is a byte-level E8/E9
  scan of `.text` plus the relocation census; the
  generator verifies recorded instruction bytes but
  does not disassemble.
- The panic-wrapper callees' internals (beyond
  format string, length, and argument passing) and
  the abort helper's callees are not analyzed; no
  claim is made about what the wrappers do with the
  field addresses beyond receiving them.
- The store FDE's remaining struct construction
  (beyond the two stores reported) is not analyzed.
- The numeric fields are reported raw; any
  line/column/version reading would be speculation.
- Static analysis only; no node execution, so no
  runtime values beyond the statically forced
  relocation values and file bytes are claimed.

## Reproduce

Target: node #94 only (91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
Static analysis only; the node binary is never executed.

Code address A maps to file offset A − 0x1000 (`.text`);
`.data.rel.ro` uses VA − 0x2000; `.rodata` uses offset
== VA; `.rela.dyn` entries are 24 bytes at file offset
`0x6bc0`. The generator fails loudly on any digest,
relocation, string, or byte mismatch.

```sh
# descriptor head slots (relocations)
readelf -r -W artifacts/node/94/hl-node | grep -E "574be20|574be28|574be30|574be38|574be40|574be48|574be60|574bf38"
# constructor + stubs
objdump -d -M intel --start-address=0x4e78660 --stop-address=0x4e78693 \
  artifacts/node/94/hl-node
# four-pair builder
objdump -d -M intel --start-address=0x4e77920 --stop-address=0x4e77a26 \
  artifacts/node/94/hl-node
# panic-wrapper uses
objdump -d -M intel --start-address=0x4e772fb --stop-address=0x4e77308 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e77e70 --stop-address=0x4e77e8f \
  artifacts/node/94/hl-node
python3 tools/be20_descriptor.py --out /tmp/bd
diff -r /tmp/bd research/work-items/RE-004-be20-descriptor-94 \
  --exclude=README.md --exclude=MANIFEST.sha256
```

Deterministic regeneration (the generator writes only to --out):

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/be20_descriptor.py --out /tmp/a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/be20_descriptor.py --out /tmp/b
diff -r /tmp/a /tmp/b   # exit 0
```

## Next question

- What are the intermediate function-pointer fields
  (`+0x70..+0x110`, relocations to small FDEs in
  the `0x4e76xxx` range) — a second slot family on
  the same descriptor, or a following record?
- What do the panic wrappers do with the field
  addresses — are the descriptor fields printed,
  compared, or stored on the panic path?
- What is the full extent of the descriptor region
  past `+0x118` (further leas at `0x574bf50` and
  beyond exist)?
- What struct does the store FDE build around the
  `[out] = descriptor` store, and who consumes it?

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — node binding, descriptor fields, FDE extents, builder
  pairs, install sites, uses, census, counts
- `slots.tsv` — 6 rows, one per descriptor slot
- `builder.tsv` — 4 rows, one per (cell, field) pair
- `uses.tsv` — 8 rows, one per neighborhood lea site
- `segments.txt` — 16 rows: 14 claim segments (423 bytes) + 2 anchor
  segments (26 bytes, #172's claims re-cited), each with start..end,
  length == end − start, file offset, and SHA-256
- `MANIFEST.sha256` — digests of the 6 files above
