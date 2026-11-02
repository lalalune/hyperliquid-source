# RE-004 trioB vtable callee resolution — node #94

## Claim status

**Claimed.** #169's trioB vtable header-2/3 verdicts —
"callee-extent-unverified" — are resolved, and the
"runtime-initialized" reading of the .data objects is
corrected:

- **Headers 2 and 3 are fully produced.** The callee on
  each route is statically fixed by a double indirection
  through load-time RELATIVE relocations: GOT slot ->
  .data object -> table first qword -> callee code.
  Header 2 lands on `0x4ea4dc0`, header 3 on
  `0x4ea3790`. Both are 30-byte twin constructors that
  write all four qwords of the 0x20-byte out layout
  (`[out+0x0]` = own table, `[out+0x8]` = rdx,
  `[out+0x10]` = rcx, `[out+0x18]` = 0), so the copy at
  `0x4e85867` reads exactly `[rsp+0x50..0x70]` —
  fully written, no stale span.
- **No runtime initializer fills the .data objects.**
  #169 read their file bytes as (0, 0, 2) and concluded
  the callee "is resolved at runtime only". The file
  bytes are indeed (0, 0, 2), but every value the routes
  use comes from a RELATIVE relocation: the .data
  objects' first two qwords are relocation addends
  (`0x574f9e0` / `0x7c5417` for header 3,
  `0x574fb08` / `0x202802` for header 2), and no code
  in `.text` references the .data objects at all (zero
  RIP-relative references, zero absolute 8-byte
  patterns). There is no initializer to find: the
  loader fixes the values, and no instruction stores
  to them.
- **Header 0 stays unresolved-indirect.** Its callee is
  `[r14+0x8]` (`0x4e85971`), and `r14` is loaded from a
  stack slot (`mov r14,[rsp+0x28]` at `0x4e8571e`),
  overwriting the entry `mov r14,rsi` (`0x4e856ff`)
  before the switch. A stack argument is runtime data,
  so no static chain resolves it. #169's verdict for
  header 0 is unchanged.

**Not claimed.** No defect, exploitability, or security
severity is claimed. The header-1-nonzero `[0x68]`
slot from #169 is untouched here and stays open. The
twin callees' table siblings (`0x1510490`,
`0x15103f0`, and the further table entries) are not
analyzed. Downstream readers of the installed objects
are #170's subject, not this packet's.

## Scope

Included:

- The trioB vtable switch block (`0x4e857c0..0x4e857d0`,
  16 B) and its 5-entry jump table (`0x7c3b84..0x7c3b98`,
  20 B, entries for headers 0–4).
- The header-2/3 indirection chains (14 rows in
  `chain.tsv`): 2 GOT slots, 2 .data objects, 2 tables,
  2 callees, 8 RELATIVE relocations by entry index.
- The two callee FDEs (`0x4ea3790..0x4ea37ae` and
  `0x4ea4dc0..0x4ea4dde`, 30 B each) with all 8 out
  stores (`callees.tsv`) and their twin comparison
  (28/30 bytes identical, 2 bytes differ).
- The header-0 open verdict: the `r14` reassignment
  (`0x4e8571e`) and the indirect-callee block
  (`0x4e8596d..0x4e85982`, anchor).
- 10 byte segments in `segments.txt` (6 claim, 95
  bytes; 4 anchors, 155 bytes, #169's claims re-cited
  with attribution; anchor digests match #169's
  exactly).

Excluded:

- The header-1 routes (zero and nonzero) and their
  assembly at `0x4e85a37`; the header-1-nonzero
  `[0x68]` slot (still open from #169).
- The trioB function's decoder inputs, the header
  computation, and the `[rbx+0x0..0x20]` destination
  object's downstream readers (see #170).
- The other 33 code references to the two GOT slots:
  the slots are shared, and only the trioB routes'
  uses are claimed here.
- The #157–#175 subjects and #1543's fixed-eight topic.

## Observations

### The switch maps headers 0–4 by bytes

The block at `0x4e857c0` (`lea rcx,[0x7c3b84]`;
`movsxd rax,[rcx+rax*4]`; `add rax,rcx`; `jmp rax`)
reads int32 entries from `0x7c3b84`:

| header | entry | target | route |
|---|---|---|---|
| 0 | `0x046c1de9` | `0x4e8596d` | `[r14+0x8]` indirect (open) |
| 1 | `0x046c1d7f` | `0x4e85903` | caller-constructed (#169) |
| 2 | `0x046c1c4c` | `0x4e857d0` | GOT `0x57732a8` -> resolved here |
| 3 | `0x046c1cc6` | `0x4e8584a` | GOT `0x57732b0` -> resolved here |
| 4 | `0x046c1ed2` | `0x4e85a56` | panic/cleanup, unreachable (#169) |

### The header-2/3 chains are relocation-only

Header 3: `mov rsi,[GOT 0x57732b0]` (`0x4e8584a`)
loads the .data object address `0x5786838` (reloc
entry 75462, RELATIVE, addend `0x5786838`). The
shared tail (`0x4e85851`, anchor) loads
`rax = [rsi]` = `0x574f9e0` (reloc entry 78766),
`rdx = [rsi+0x8]` = `0x7c5417` (reloc entry 78767),
`rcx = [rsi+0x10]` = 2 (file value, no reloc), then
`rsi += 0x18`, `rdi = [rsp+0x50]` (out), and
`call [rax]` — i.e. `call [0x574f9e0]` =
`0x4ea3790` (reloc entry 62708).

Header 2 mirrors it: `mov rsi,[GOT 0x57732a8]`
(`0x4e857d0`) loads `0x5786858` (entry 75461);
`[rsi]` = `0x574fb08` (entry 78768),
`[rsi+0x8]` = `0x202802` (entry 78769),
`[rsi+0x10]` = 2 (file value); `call [0x574fb08]` =
`0x4ea4dc0` (entry 62728).

The .data objects are reached only through the GOT
slots: a full `.text` scan finds zero RIP-relative
references and zero absolute 8-byte patterns for
`0x5786838` / `0x5786858` / `0x5786840` /
`0x5786860`. No instruction writes to them, so no
runtime initializer exists to trace — the
"runtime-initialized" label in #169's
vtable-routes.tsv is superseded by "load-time
relocated".

The GOT slots themselves are shared: 26 code sites
load `0x57732a8` and 9 load `0x57732b0`. Only the
trioB routes' loads (`0x4e857d0`, `0x4e8584a`)
are claimed here; the other readers are out of scope.

### The twin callees fully write the out layout

`0x4ea3790` (header 3) and `0x4ea4dc0` (header 2)
are 30-byte FDEs with identical structure:

```
mov rax,rdi
mov [rdi+0x8],rdx
mov [rdi+0x10],rcx
mov [rdi+0x18],0x0
lea rcx,[table]      ; 0x574f9e0 (H3) / 0x574fb08 (H2)
mov [rdi],rcx
ret
```

Each writes `[out+0x0]` (own table), `[out+0x8]`
(rdx: `0x7c5417` / `0x202802`, .rodata pointers),
`[out+0x10]` (rcx: 2), `[out+0x18]` (0) — the full
0x20 bytes. The two bodies differ in exactly 2 bytes
(offsets 22–23, the `lea` disp32 low bytes);
28/30 bytes are identical. Each table's sole code
reference is its own callee's self-install `lea`;
no other code loads `0x574f9e0` or `0x574fb08`.

The copy at `0x4e85867` (anchor) then reads
`[rsp+0x50..0x70]` into `[rbx+0x0..0x20]` — exactly
the span the callee just wrote. The header-2/3
installed objects are therefore fully produced, not
stale, and not extent-unverified.

### Header 0: r14 is a stack argument

The trioB function (`0x4e856f0..0x4e85b12`) opens
with `mov r14,rsi` (`0x4e856ff`), but before the
switch it executes `mov r14,[rsp+0x28]`
(`0x4e8571e`), so at the header-0 block
(`0x4e8596d`, anchor) `r14` is whatever the caller
passed on the stack. The callee `[r14+0x8]`
(`0x4e85971`), with `rdx = [r14+0x10]`,
`rcx = [r14+0x18]`, `rsi = [r14+0x20]`, and the
shared tail's `call [rax]`, cannot be resolved
statically. Header 0's verdict is unchanged.

## Inferences (separated from observations)

- #169's "callee-extent-unverified" for headers 2
  and 3 was an artifact of reading file bytes instead
  of relocations. With relocations applied, both
  callees are known functions with complete 0x20-byte
  write extents, and the verdict flips to
  fully-produced.
- The pattern is a load-time vtable install, not a
  runtime dispatch table: the .data objects are
  immutable-after-load descriptors (table, rodata
  pointer, count 2), the GOT slots are just address
  conduits, and the twin constructors stamp the
  table pointer into every object they build.
- The correction is narrow: it changes only the
  header-2/3 callee verdicts. Header 0, header 1,
  and every other #169 verdict stand as published.

## Limitations

- The "no code reference to the .data objects"
  census rests on the full `.text` objdump census
  (RIP-relative comment scan) plus an absolute
  8-byte pattern scan of `.text`; the generator
  verifies the recorded relocation entries but does
  not disassemble.
- The .rodata pointers (`0x7c5417`, `0x202802`)
  are reported as pointers only; their target
  contents are not interpreted (bytes at the
  targets begin with short prefixes followed by
  printable strings, but no semantic claim is made
  about them).
- The other 33 GOT-slot readers are not traced;
  no claim is made about what they do with the
  .data object addresses.
- Static analysis only; no node execution, so no
  runtime values beyond the statically forced
  relocation values are claimed.

## Reproduce

Target: node #94 only (91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
Static analysis only; the node binary is never executed.

Code address A maps to file offset A − 0x1000 (`.text`);
`.rodata` uses offset == VA; `.data.rel.ro` and `.got`
use VA − 0x2000; `.data` uses VA − 0x3000; `.rela.dyn`
entries are 24 bytes at file offset `0x6bc0`. The
generator fails loudly on any digest, relocation, or
byte mismatch.

```sh
# switch block and header-2/3 GOT loads
objdump -d -M intel --start-address=0x4e857c0 --stop-address=0x4e857d7 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e8584a --stop-address=0x4e85851 \
  artifacts/node/94/hl-node
# twin callees
objdump -d -M intel --start-address=0x4ea3790 --stop-address=0x4ea37ae \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4ea4dc0 --stop-address=0x4ea4dde \
  artifacts/node/94/hl-node
# relocation chain (entries 75461/75462, 78766-78769, 62708/62728)
readelf -r -W artifacts/node/94/hl-node | grep -E "57732a8|57732b0|5786838|5786840|5786858|5786860|574f9e0|574fb08"
python3 tools/triob_vtable_callees.py --out /tmp/tvc
diff -r /tmp/tvc research/work-items/RE-004-triob-vtable-callee-resolution-94 \
  --exclude=README.md --exclude=MANIFEST.sha256
```

Deterministic regeneration (the generator writes only to --out):

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/triob_vtable_callees.py --out /tmp/a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/triob_vtable_callees.py --out /tmp/b
diff -r /tmp/a /tmp/b   # exit 0
```

## Next question

- Can header 0's `[r14+0x8]` callee be resolved from
  the trioB callers — i.e. what do callers pass as the
  stack argument that becomes `r14` (`[rsp+0x28]` at
  `0x4e8571e`)?
- What are the table siblings (`0x1510490`,
  `0x15103f0`, and the further entries of tables
  `0x574f9e0` / `0x574fb08`), and do they share the
  twin-constructor shape?
- What do the other 33 GOT-slot readers do with the
  .data object addresses — do any of them store to
  the objects, which would reopen the "immutable
  after load" reading?
- The header-1-nonzero `[0x68]` slot (from #169)
  is still open.

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — node binding, FDE extents, switch
  mapping, relocation chain, twin comparison, verdicts
- `chain.tsv` — 14 rows, one per indirection step
- `callees.tsv` — 8 rows, one per out store
- `segments.txt` — 10 rows: 6 claim segments (95 bytes)
  + 4 anchor segments (155 bytes, #169's claims
  re-cited), each with start..end, length == end −
  start, file offset, and SHA-256
- `MANIFEST.sha256` — digests of the 5 files above
