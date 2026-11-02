# RE-004 be20 location run — node #94

## Claim status

**Claimed.** #178's Next question — what is the `+0x118`
array (0x18-byte entries) after the be20 descriptor region,
a location table for the descriptor region or the next
record's header? — is answered: it is neither. It is a
contiguous run of 26 Rust `core::panic::Location`
records (`0x574bf38..0x574c1a8`, 26 x 0x18 bytes =
624 bytes), each individually cited by panic call sites
in code. The be20 descriptor region ends at `0x574bf38`;
this run starts exactly there and is a distinct object.

- **The run is 26 Location records.** Each record is
  [file-pointer (RELATIVE reloc), file length, line
  u32, column u32]: the file pointer resolves to a
  `.rodata` source path, the length matches that path
  exactly, and line/column are plausible source
  positions. Relocation indices are contiguous
  (61887–61912), immediately after #178's 61875–61886.
- **Every record is cited by code.** A full `.text`
  objdump census finds 35 `lea` sites loading run
  entries: 32 into `rdi`, 2 into `rcx`, 1 into `rdx`.
  No entry is unreferenced, and no whole-run
  (pointer, length) fat pointer exists anywhere in the
  file — the run is cited entry by entry, never as one
  slice.
- **The sites consume through 6 GOT slots.** 22 sites
  call indirectly through a GOT slot right after the
  `lea`; 13 sites jump or fall through into shared
  continuations that call GOT `0x576e470`. The GOT
  slots resolve to 6 low-`.text` runtime helpers,
  four of which share one shape (message pointer,
  length, location in `rdx` → runtime call → `int3`),
  one of which is a bounds-check shape, and one of
  which builds a two-word stack pair before calling on.

**Not claimed.** No defect, exploitability, or security
severity is claimed. The std-internal names of the
runtime helpers are not identified (only their
instruction shapes and message spans are reported).
Whether the run is one array object or 26 grouped
statics is not determined from static evidence (no
whole-run reference exists either way). The
journaled_state plurality (14/26) next to #177's
journaled_state header string is adjacency, not a
proven link to the be20 descriptor.

## Scope

Included:

- The 26 Location records (`locations.tsv`): file,
  line, column, relocations, string lengths.
- The 35 `lea` citation sites (`sites.tsv`): site
  address, entry, register, follow shape, GOT slot or
  continuation target.
- The 6 GOT slot resolutions and the runtime helper
  shapes, including message spans.
- 26 byte segments in `segments.txt` (26 claim, 624
  bytes; 0 anchors — no prior packet claims any of
  these bytes).

Excluded:

- The be20 descriptor header and four records
  (`0x574be20..0x574bf38` — #177's and #178's
  subjects, cited only as the boundary); the
  four-pair builder FDE (#177's subject); the
  `0x574c1a8` object (`0, 1, 1`, no reloc) and the
  `0x574c1c0` object (reloc to `0x4e7c780`, `0`, 100)
  — reported as the run's boundary only, not
  analyzed; the #157–#178 subjects; #1543's
  fixed-eight topic; #176's header-0 /
  decoder-out+8 question (not touched here).

## Observations

### The run layout

| piece | range | size | content |
|---|---|---|---|
| be20 region | `0x574be20..0x574bf38` | 0x118 | header + 4 records (#177/#178) |
| location run | `0x574bf38..0x574c1a8` | 0x270 | 26 x 0x18 Location records |
| next object | `0x574c1a8..` | — | `(0, 1, 1)`, no reloc (out of scope) |

### Files in the run

| file | entries | lines |
|---|---|---|
| `revm-19.2.0/src/handler/mainnet/pre_execution.rs` | 3 | 65:44, 178:9, 157:13 |
| `ruint-1.12.3/src/algorithms/mul.rs` | 1 | 113:23 |
| `revm-19.2.0/src/journaled_state.rs` | 14 | 332:45, 347:59, 360:61, 339:45, 366:53, 368:49, 372:45, 372:21, 375:64, 399:26, 402:26, 386:26, 389:26, 420:55 |
| `ruint-1.12.3/src/bits.rs` | 1 | 296:42 |
| `revm-interpreter-15.0.0/src/interpreter/shared_memory.rs` | 5 | 268:28, 277:50, 171:19, 117:9, 146:34 |
| `revm-interpreter-15.0.0/src/instructions/system.rs` | 2 | 175:59, 175:44 |

Full paths carry the prefix
`/home/ubuntu/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/`.
Record lengths (114/100/100/90/122/116) equal the full
path lengths exactly, and each `.rodata` string ends
with `.rs`.

### Citation sites

35 sites in `0x4e77e70..0x4e7b482`, per entry:

- Entries 0–18, 23–25: 1 site each.
- Entry 19 (`shared_memory.rs` 268:28): 3 sites
  (`0x4e7a5ea`, `0x4e7a819`, `0x4e7b0ae`).
- Entry 20 (`shared_memory.rs` 277:50): 3 sites
  (`0x4e7a5f7`, `0x4e7a826`, `0x4e7b0bb`).
- Entry 21 (`shared_memory.rs` 171:19): 3 sites
  (`0x4e7a5dd`, `0x4e7a7ff`, `0x4e7b094`).
- Entry 22 (`shared_memory.rs` 117:9): 4 sites
  (`0x4e7a80c`, `0x4e7ab2e`, `0x4e7b0a1`, `0x4e7b475`).

Registers: `rdi` 32, `rcx` 2 (entries 3 and 24),
`rdx` 1 (entry 0). The two `rcx` sites feed the
bounds-check helper, whose body moves `rcx` into the
location slot (`mov rdx,rcx`) before its runtime
call — the register matches the helper's convention.

### Consumption shapes

Direct indirect-call sites (22): `lea` entry, then
`call [GOT slot]`, then `int3` padding (noreturn
shape). GOT histogram: `0x576e118` x9, `0x576e150`
x9, `0x576e2e0` x2, `0x576e468` x1, `0x576e1b0` x1.

Continuation sites (13): `lea` entry, then `jmp` to
`0x4e7a4bd` (11 sites) or to `0x4e7a4c6` (1 site,
entry 17), or fall-through into `0x4e7a4bd` (1 site,
entry 6). The continuation restores `rbx`/`r14` and
calls GOT `0x576e470`. All 13 continuation sites
therefore funnel to the same runtime helper.

### Runtime helpers (shapes only)

| GOT slot | helper | shape |
|---|---|---|
| `0x576e118` | `0x157b480` | msg ptr `0x252cf8`, len 57, loc in `rdx` → call `0x576e098` → `int3` |
| `0x576e150` | `0x157b520` | msg ptr `0x252d9b`, len 67, loc in `rdx` → call `0x576e098` → `int3` |
| `0x576e1b0` | `0x157b4a0` | msg ptr `0x252d14`, len 67, loc in `rdx` → call `0x576e098` → `int3` |
| `0x576e470` | `0x157a9f0` | msg ptr `0x256638`, len 43, loc in `rdx` → call `0x576e108` → `int3` |
| `0x576e2e0` | `0x157a6f0` | bounds-check: `cmp rdi,rdx; jbe skip`, else build args, loc from `rcx` → call `0x576e098` |
| `0x576e468` | `0x157a9b0` | store `rdi`/`rsi` pair to stack, load `0x15700f0` + arg `0x1ea44d`, loc from `rdx` → call `0x576e098` |

Message spans: `0x157a9f0`'s span is exactly one
message, ``called `Option::unwrap()` on a `None`
value`` (43 bytes). The three arithmetic helpers'
spans start at message starts but their recorded
lengths run past the first message into the next
packed message: `0x157b480` (57 bytes from
"attempt to add with overflow", 28 bytes, into
"attempt to multiply with overflow"); `0x157b520`
(67 bytes from "attempt to subtract with overflow",
33 bytes, into "assertion failed: other > 0");
`0x157b4a0` (67 bytes from "attempt to multiply
with overflow", 33 bytes, into "attempt to negate
with overflow"). Messages in `.rodata` are packed
with no separators. What the `0x576e098`/`0x57706e0`
chain does with the (pointer, length) pair — i.e.
why the recorded lengths span messages — is NOT
determined here (see Limitations).

### Boundary

`0x574c1a8` holds file values `(0, 1, 1)` with no
relocation: it is not a 27th Location record. The
run is exactly 26 entries. What follows
(`0x574c1c0`: reloc to code `0x4e7c780`, `0`, 100)
is a different object, not analyzed.

## Inferences (separated from observations)

- The record shape (file pointer + length + line +
  column) together with the noreturn call shapes and
  the unwrap message identifies these as Rust panic
  Location records: each site reports a source
  position to the panic runtime.
- The run's contiguity, uniform 0x18 stride, and
  contiguous relocation block are consistent with
  linker grouping of Location statics from several
  crates (revm, ruint, revm-interpreter), but no
  whole-run reference exists, so a single array
  object is not established.
- The journaled_state plurality (14/26) beside
  #177's journaled_state header string suggests the
  run's producers overlap the be20 descriptor's
  component, but adjacency alone does not prove the
  run belongs to that component.

## Prior work and overlap

Segment-claim overlap with #157–#178 is zero bytes
(verified against the submitted packets' segments;
#178's last claim ends exactly at this packet's
first byte `0x574bf38` with no overlap). No anchors:
no prior claim is re-cited. The candidate directory
name is absent from live upstream main (trees API
recursive, not truncated). No competing open PR
matched the searches (be20+location, location+table,
panic+location, loc+table). #176's header-0 /
decoder-out+8 question is untouched by this packet
and remains open.

## Verification

- Target: node #94 only (91,774,280 bytes, SHA-256
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
  Static analysis only; the node binary was never executed.
- Generator (tools/be20_location_run.py) verifies the node
  digest and size first, checks every record's file bytes
  (reloc slot 0, length, line, column), every RELATIVE
  relocation by .rela.dyn entry index (entries are 24 bytes
  at file offset `0x6bc0`), every `.rodata` file-path string,
  every site's 7-byte `lea` encoding with disp32 resolving
  to its entry (code address A at file offset A - 0x1000;
  `.data.rel.ro` address A at file offset A - 0x2000),
  the 6 GOT resolutions, and the 4 message-span prefixes,
  then writes only to --out. Regeneration in two directories
  with different PYTHONHASHSEED/TZ is byte-identical and
  matches the packet files (README/MANIFEST excluded).
- MANIFEST.sha256: 5/5 OK. Unit tests: 6/6 pass
  (tests/test_be20_location_run.py). make doctor:
  analysis_ready true. make verify: exit 0. make
  catalogue-check: exit 0. make test: Ran 448 tests, OK (442
  baseline + 6 new, 0 regressions).
- Reproduce: objdump -d -M intel --start-address=<site>
  artifacts/node/94/hl-node for any site in sites.tsv;
  readelf -r -W artifacts/node/94/hl-node | grep 574bf
  for the run's relocations; code address A maps to file
  offset A - 0x1000; `.data.rel.ro` uses VA - 0x2000;
  `.rela.dyn` entries are 24 bytes at file offset `0x6bc0`.

## Limitations

- The generator verifies recorded instruction bytes but
  does not disassemble; the site census rests on the
  full `.text` objdump census (lea target comment scan).
- The runtime helpers are characterized by instruction
  shape and message spans only; their std-internal names
  and the exact message-selection semantics of the
  `0x576e098`/`0x57706e0` chain (including why the
  arithmetic helpers' recorded lengths span packed
  messages) are not determined.
- The enclosing FDEs of the 35 sites are not attributed
  here; sites are reported by address and follow shape.
- Static analysis only; no node execution, so no runtime
  values beyond the statically forced relocation values
  and file bytes are claimed.

## Next question

- What does the `0x576e098`/`0x57706e0` chain do with
  the (pointer, length) pair — why do the arithmetic
  helpers' recorded lengths span packed messages?
- Which FDEs contain the 35 sites, and do the 13
  continuation sites share one caller function?
- What is the `0x574c1a8` object (`0, 1, 1`) and the
  `0x574c1c0` object (reloc to `0x4e7c780`) that follow
  the run — the next record's header, or unrelated data?
- #176's header-0 question remains open: what does
  decoder `0x4e84500` write to out+8 on the tag==5 path
  (corrected framing — not a caller stack argument)?

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — node binding, run layout, site counts, GOT map, counts
- `locations.tsv` — 26 rows, one per Location record
- `sites.tsv` — 35 rows, one per citation site
- `segments.txt` — 26 rows: 26 claim segments (624 bytes),
  each with start..end, length == end − start, file offset,
  and SHA-256
- `MANIFEST.sha256` — digests of the 5 files above
