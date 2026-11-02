# RE-004 oc table builder — node #94

## Claim status

**Claimed.** #171's Next question — is there an indirect (vtable)
caller of the orchestrator's callers, and do the callers' callers
read the propagated residue? — is answered structurally for the
first half: oc1/oc2/oc3 (the three direct callers of the
orchestrator from #171) have **no direct callers and no direct
references anywhere**. They are reachable only as function pointers
in element 6 of an 11-element `.data.rel.ro` table, which a builder
function materializes into an 11-pair output struct that its sole
caller copies onward with memcpy. The residue's third-boundary
reader, if one exists, must live behind this table indirection.

**Not claimed.** No indirect call through the pair array is
witnessed: the builder's output is copied by its caller to
`[rsp+0x388]`, and `[rsp+0x388]` is not read later in the caller
FDE. The packet claims the reachability structure (table + builder
+ copy), not an observed invocation of oc1/oc2/oc3. No defect,
exploitability, or security severity is claimed.

## Scope

Included:

- The 3 oc functions from #171 (oc1 `0x4e6cfe0`, oc2 `0x4e6d690`,
  oc3 `0x4e6e7d0`) and the census of their references: direct
  calls, RIP-relative references, relocations, init/fini arrays.
- The 11-element table at `0x574bc10..0x574be20` (528 bytes,
  stride 48): 11 elements × {qword 0, qword 0, qword 1, fn, fn, fn},
  33 function slots, all RELATIVE-relocated.
- The builder FDE `0x4e72b40..0x4e730a5` (1381 bytes): 11
  allocation calls, 11 (cell, table-element) pairs, 176-byte
  output struct.
- The builder's sole direct caller (FDE `0x4e7d360..0x4e7d678`,
  792 bytes; call site `0x4e7d4a3`) and its memcpy of the
  176-byte output.
- The separate `0x574be20` object and its 2 referencing code
  sites (setter + store function).

Excluded:

- Invocation through the pair array (not observed; see Next
  question), the internals of the 33 table functions other than
  oc1/oc2/oc3, the `0x574be20` object's internal semantics
  (its 6 neighborhood references are listed, not traced), the
  builder's landing-pad cleanup (not traced), and the
  `0x54c8cb0` shared callee (cited only as a call-target address
  elsewhere, never analyzed). The #157–#171 subjects and #1543's
  fixed-eight topic are cited, not re-claimed.

## Observations

### Zero direct references to oc1/oc2/oc3

- Full `.text` scan for `E8` + rel32 and `E9` + rel32 resolving
  to `0x4e6cfe0`, `0x4e6d690`, `0x4e6e7d0`: **0 hits** for each
  target, both opcodes.
- Full `.text` scan for RIP-relative instructions resolving to
  any oc address (REX and non-REX forms): **0 hits**.
- Relocation census over `.rela.dyn` + `.rela.plt`: exactly **3**
  entries reference an oc target, all RELATIVE (type 8),
  consecutive `.rela.dyn` entries 61853–61855:
  slot `0x574bd48` → oc3, slot `0x574bd50` → oc2,
  slot `0x574bd58` → oc1.
- `.init_array` (168 entries) and `.fini_array` (1 entry):
  no oc address.

### The table: 11 elements, oc trio in element 6

Each element is 48 bytes: `[+0x00] = 0`, `[+0x08] = 0`,
`[+0x10] = 1`, `[+0x18]`, `[+0x20]`, `[+0x28]` = three function
pointers (RELATIVE relocations). Full list in `table.tsv`.

| element | base | f0 | f1 | f2 |
|---|---|---|---|---|
| 0 | `0x574bc10` | `0x4e6e850` | `0x4e6df40` | `0x4e6cf80` |
| 1 | `0x574bc40` | `0x4e6e4c0` | `0x4e6dcb0` | `0x4e6cd80` |
| 2 | `0x574bc70` | `0x4e6e050` | `0x4e6ddf0` | `0x4e6d210` |
| 3 | `0x574bca0` | `0x4e6e680` | `0x4e6d9e0` | `0x4e6d0c0` |
| 4 | `0x574bcd0` | `0x4e6e320` | `0x4e6d970` | `0x4e6cf10` |
| 5 | `0x574bd00` | `0x4e6e1a0` | `0x4e6db30` | `0x4e6d360` |
| **6** | **`0x574bd30`** | **oc3 `0x4e6e7d0`** | **oc2 `0x4e6d690`** | **oc1 `0x4e6cfe0`** |
| 7 | `0x574bd60` | `0x4e6e600` | `0x4e6d8f0` | `0x4e6d4e0` |
| 8 | `0x574bd90` | `0x4e6dfa0` | `0x4e6d710` | `0x4e6d060` |
| 9 | `0x574bdc0` | `0x4e6e000` | `0x4e6d8a0` | `0x4e6cec0` |
| 10 | `0x574bdf0` | `0x4e6e390` | `0x4e6d770` | `0x4e6d560` |

Boundary: the preceding qwords (`0x574bbf0..0x574bc08` =
`0x9000001bb`, `0`, `0x6e`, `0x1c00000164`) do not fit the
`{0, 0, 1, fn, fn, fn}` shape, so the array starts cleanly at
`0x574bc10` and ends at `0x574be20`.

### The builder: 11 cells, 11 pairs, 176 bytes

The builder (`0x4e72b40..0x4e730a5`) makes **11** allocation
calls through GOT slot `0x576dfd8` (RELATIVE-resolved to local
`0x54c06b0`), each requesting `0x10` bytes in `edi` with a
null check, and initializes every cell to `{1, 1}`. It then
assembles 11 (cell, table-element) pairs into the `rdi` output
object (`rbx`), 16 bytes per pair, 176 bytes total
(`[rbx+0x00..0xb0]`). Full list in `pairs.tsv`; the 21
element leas (10 malloc-phase + 11 assembly-phase) are in
`builder-leas.tsv`.

| pair | output offset | cell | element | element base |
|---|---|---|---|---|
| 1 | `0x00` | C1 | 4 | `0x574bcd0` |
| 2 | `0x10` | C2 | 5 | `0x574bd00` |
| **3** | **`0x20`** | **C3** | **6 (oc)** | **`0x574bd30`** |
| 4 | `0x30` | C4 | 0 | `0x574bc10` |
| 5 | `0x40` | C5 | 1 | `0x574bc40` |
| 6 | `0x50` | C6 | 7 | `0x574bd60` |
| 7 | `0x60` | C7 | 8 | `0x574bd90` |
| 8 | `0x70` | C8 | 2 | `0x574bc70` |
| 9 | `0x80` | C9 | 9 | `0x574bdc0` |
| 10 | `0x90` | C10 | 10 | `0x574bdf0` |
| 11 | `0xa0` | C11 | 3 | `0x574bca0` |

The oc pair is pair 3: `[rbx+0x20] = C3`,
`[rbx+0x28] = 0x574bd30` (segment `oc-pair-stores`). A
consumer holding the pair array reaches oc1/oc2/oc3 through
`[element+0x18]`, `[element+0x20]`, `[element+0x28]` — never
by direct call. Note: the intermediate (cell, table) stack
slots written during construction are not read on the normal
path; the final assembly re-derives table addresses with
fresh leas and reads cells from registers/spills.

### The builder's caller copies the array onward

The builder has exactly **1** direct caller: `0x4e7d4a3`
in FDE `0x4e7d360..0x4e7d678`, passing `rdi = [rsp+0x1f0]`
as the output buffer. After the call, the caller copies the
whole 176-byte output with memcpy (`r15`, loaded from GOT
`0x576dfe0`, JUMP_SLOT symbol `memcpy`): `rdi = [rsp+0x388]`,
`rsi = [rsp+0x1f0]`, `edx = 0xb0` (segment `memcpy-site`).
`[rsp+0x388]` is not read later in the caller FDE — the
chain goes cold here (see Next question).

### The separate 0x574be20 object

`0x574be20` is **not** a 12th table element: its first
fields are six consecutive RELATIVE pointers
(`0x4e78670`, `0x1510490`, `0x15103f0`, `0x4e78690`,
`0x4e78660`, `0x1ea965`), not `{0, 0, 1, fn, fn, fn}`.
It is referenced by exactly 2 code sites:

- Tiny setter FDE `0x4e78670..0x4e7868e` (30 bytes):
  `lea rcx,[0x574be20]; mov [rdi],rcx; ret`.
- Store FDE `0x4e76900..0x4e76af5` (501 bytes):
  at `0x4e76a70`, `lea rcx,[0x574be20]; mov [rdx],rcx`
  with `rdx = [rsp+0x20]`.

Its first slot points back at the setter itself
(`0x4e78670`). Its internal semantics are not analyzed.

### RIP census: 29 sites, nothing else

A RIP-relative scan over `[0x574bc10, 0x574bf00)`
finds exactly **29** instructions: 21 builder leas (all 11
element bases), 2 leas to `0x574be20`, and 6 leas to
`0x574be20`-neighborhood slots (`0x574be48`, `0x574be60`,
`0x574be78` × 2, `0x574bea8`, `0x574bed8`, in the
`0x4e77xxx` region, not analyzed). No other code in
`.text` references the table range.

## Inferences (separated from observations)

- The oc trio's reachability is table-driven, not
  call-driven: the only static path from code to oc1/oc2/oc3
  runs through element 6's slots via the builder's pair
  array. A reader of the propagated residue behind this
  indirection must first obtain the pair array (or the
  element pointer) and dispatch through it.
- The builder's output ordering is not element order
  (pairs run 4, 5, 6, 0, 1, 7, 8, 2, 9, 10, 3), so a
  consumer cannot assume pair index == element index;
  the element pointer in each pair is the routing fact.
- The `{1, 1}` cell initialization and the `{0, 0, 1}`
  element header are structural constants of this
  mechanism, but their semantic roles (refcount? tag?
  version?) are not determined here.

## Limitations

- No witnessed indirect call through the pair array:
  the chain is traced to the caller's memcpy destination
  `[rsp+0x388]`, which is not read later in the caller
  FDE. Whether any code reads `[rsp+0x388]` or dispatches
  through element 6 is the Next question.
- The `0x574be20` object and its 6 neighborhood
  references are listed, not analyzed; no claim is made
  about what they do.
- The builder's landing-pad cleanup (from `0x4e72f78`)
  is not traced; all pair claims are normal-path only.
- The allocation call through GOT `0x576dfd8` is
  described functionally (0x10-byte requests,
  null-checked, RELATIVE-resolved to local `0x54c06b0`);
  it is not identified as libc malloc.
- Direct-call and RIP scans cover `.text` only;
  `.init`/`.plt` are import stubs and hold no oc
  references, and init/fini arrays were checked
  separately. Static analysis only; no node execution.

## Reproduce

Target: node #94 only (91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
Static analysis only; the node binary is never executed.

Code address A maps to file offset A − 0x1000 (`.text`);
`.data.rel.ro` VA maps to file offset VA − 0x2000. The
generator fails loudly on any digest, relocation, lea,
malloc, store, call-site, or scan mismatch.

```sh
# the table: fn slots are RELATIVE relocations (file bytes are 0);
# read the addends from .rela.dyn (off 0x6bc0, 24-byte entries)
python3 -c "import struct; d = open('artifacts/node/94/hl-node','rb').read(); \
  rel = {struct.unpack('<Q', d[0x6bc0+i*24:0x6bc0+i*24+8])[0]: \
  struct.unpack('<q', d[0x6bc0+i*24+16:0x6bc0+i*24+24])[0] \
  for i in range(0x1d4e10//24)}; \
  print([hex(rel[0x574bc10+0x18+8*k]) for k in range(3)]); \
  print([hex(rel[0x574bd30+0x18+8*k]) for k in range(3)])"
# the builder's oc-pair stores
objdump -d -M intel --start-address=0x4e72df3 --stop-address=0x4e72e07 \
  artifacts/node/94/hl-node
# the builder call site and the memcpy site
objdump -d -M intel --start-address=0x4e7d4a3 --stop-address=0x4e7d4a8 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e7d594 --stop-address=0x4e7d5ac \
  artifacts/node/94/hl-node
# the elem11 setter
objdump -d -M intel --start-address=0x4e78683 --stop-address=0x4e7868e \
  artifacts/node/94/hl-node
python3 tools/oc_table_builder.py --out /tmp/oc-table
diff -r /tmp/oc-table research/work-items/RE-004-oc-table-builder-94 \
  --exclude=README.md --exclude=MANIFEST.sha256
```

Deterministic regeneration (the generator writes only to --out):

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/oc_table_builder.py --out /tmp/a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/oc_table_builder.py --out /tmp/b
diff -r /tmp/a /tmp/b   # exit 0
```

## Next question

- Who reads the caller's `[rsp+0x388]` copy of the pair
  array — and does any code dispatch through element 6's
  slots (`[0x574bd30+0x18/0x20/0x28]`, i.e. oc3/oc2/oc1),
  finally consuming (or further propagating) the residue
  behind the table indirection?
- What is the `0x574be20` object, and what do its 6
  neighborhood references (`0x4e77xxx` region) do with it?

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — table summary, reloc census, builder/caller
  facts, scan results, segment inventory
- `table.tsv` — 11 rows, one per table element
- `pairs.tsv` — 11 rows, one per builder output pair
- `builder-leas.tsv` — 21 rows, one per builder element lea
- `sites.tsv` — FDEs, call sites, reloc entries, scan summaries
- `segments.txt` — 7 claim segments (641 bytes), each with
  start..end, length == end − start, file offset, and SHA-256
- `MANIFEST.sha256` — digests of the 7 files above
