# RE-004 be20 mid-table — node #94

## Claim status

**Claimed.** #177's first Next question — are the intermediate
function-pointer fields (`+0x70..+0x110`, relocations to small
FDEs in the `0x4e76xxx` range) a second slot family on the
same descriptor, or a following record? — is answered: they
are a four-entry table that belongs to the be20 descriptor
region itself, and the #177 four-pair builder points at it.

- **The mid-fields are four 0x30-byte records.**
  Immediately after the 0x58-byte descriptor header
  (`0x574be20..0x574be78`), four records follow at
  `0x574be78`, `0x574bea8`, `0x574bed8`, `0x574bf08`
  (0x30 apart). Each record is `[0, 0, 1, fn, fn, fn]`:
  three file-value qwords (0, 0, 1, no relocations) and
  three RELATIVE-relocated function slots. The record
  bases are exactly the four pair-field addresses the
  #177 builder builds pairs for, so the table is the
  builder's target, not a following record.
- **Each record's fn triple shares one shape.**
  Record 0's triple is three 32-byte functions, record
  1's is three 152-byte functions, record 2's is three
  17-byte wrappers, record 3's is three 17-byte
  wrappers. Within each triple the bodies differ only
  in address-dependent displacement low bytes (4/4/2
  bytes for record 0, 8/8/4 for record 1, 1–2 for
  records 2 and 3) — the triples are clones modulo
  addressing, not three unrelated functions that happen
  to share a slot.
- **The twelve functions are reachable only via the
  table.** Each fn target has exactly one `.rela.dyn`
  entry (its own record slot), and a full `.text`
  objdump census finds zero direct E8 calls and zero
  direct E9 jumps to any of the twelve. No code calls
  them by address; the table slots are the only
  recorded route.

**Not claimed.** No defect, exploitability, or security
severity is claimed. The semantics of the shared callees
beyond their heads and FDE sizes are not identified.
Who consumes the builder's pair struct — i.e. who
dispatches through these table slots — is not traced
here. The descriptor's identity (what type or component
it describes) is not identified.

## Scope

Included:

- The be20 descriptor region layout: header
  `0x574be20..0x574be78` (0x58 bytes, #177's subject,
  not re-claimed) + four records `0x574be78..0x574bf38`
  (4 x 0x30 bytes) = 0x118 bytes total.
- The four records (`records.tsv`): bases, prefixes,
  fn triples, triple sizes, shapes, shared callees.
- The twelve fn FDEs (`triples.tsv`): exact extents,
  pairwise body-difference offsets, shared callees.
- The 12 RELATIVE relocations (entries 61875–61886)
  and the exclusivity census (1 relocation per fn
  target, 0 direct E8/E9 callers).
- 16 byte segments in `segments.txt` (16 claim, 750
  bytes; 0 anchors — no prior packet claims any of
  these bytes).

Excluded:

- The descriptor header itself (6 slots, numerics,
  strings — #177's subject); the four-pair builder
  FDE and its pair-field leas (#177's subject, cited
  only as the linkage); the `+0x118` array (0x18-byte
  entries: string + 114/100 + packed value — a
  distinct array, not analyzed); the #157–#177
  subjects and #1543's fixed-eight topic.

## Observations

### The region layout

| piece | range | size | content |
|---|---|---|---|
| header | `0x574be20..0x574be78` | 0x58 | 6 slots + 99 + packed + string + 100 + packed (#177) |
| record 0 | `0x574be78..0x574bea8` | 0x30 | `[0, 0, 1, fn, fn, fn]` |
| record 1 | `0x574bea8..0x574bed8` | 0x30 | `[0, 0, 1, fn, fn, fn]` |
| record 2 | `0x574bed8..0x574bf08` | 0x30 | `[0, 0, 1, fn, fn, fn]` |
| record 3 | `0x574bf08..0x574bf38` | 0x30 | `[0, 0, 1, fn, fn, fn]` |
| next array | `0x574bf38..` | 0x18/entry | string + 114/100 + packed (out of scope) |

The record bases are the builder's pair fields
(#177 `builder.tsv`: pairs 1–4 point at `0x574be78`,
`0x574bea8`, `0x574bed8`, `0x574bf08`). The builder
stores record addresses, never record contents — the
same by-address consumption shape #177 found for the
header fields.

### The four triples

Record 0 — 32-byte allocator-out triple
(`0x4e76de0`, `0x4e76cc0`, `0x4e76bc0`):

```
push rbx; rbx = rdi
lea rdi,[0x5788448]      ; .bss address
call 0x4e9a310            ; 1421-byte FDE
[rbx] = 0; [rbx+0x8] = rax; return rbx
```

Pairwise body differences: fn1–fn2 at bytes 7, 8, 12,
13; fn1–fn3 at 7, 8, 12, 13; fn2–fn3 at 8, 13 — the
`lea` disp32 low bytes and the `call` disp32 low
bytes only. Same target addresses, different
instruction addresses: the triple is one function
instantiated three times.

Record 1 — 152-byte copy-with-tag5-branch triple
(`0x4e76d40`, `0x4e76c20`, `0x4e76b20`):

```
r14 = rdx; rbx = rdi
[rdx+0xb0] = 0xff
copy 0x14 bytes from [rdx+0xd8] area to stack
r15 = rdx+0x80; call 0x4e8c640 twice (stack chunk, then rodata chunk)
call 0x4e77390 (stack chunk, r14)
if [rsp] == 5: [rbx] = 5
else: movups [rbx] = [rsp], [rbx+0x10] = [rsp+0x10]
return rbx
```

Pairwise differences: fn1–fn2 and fn1–fn3 at bytes 67,
68, 74, 75, 97, 98, 108, 109; fn2–fn3 at 68, 75, 98,
109 — the three `call` disp32 low bytes and the one
rip-relative `movups` disp32 low bytes only. The tail
(bytes 110–151, including the tag-5 branch) is
byte-identical across the triple.

Record 2 — 17-byte wrapper triple
(`0x4e76d20`, `0x4e76ce0`, `0x4e76b00`):

```
push rbx; rbx = rdi; rsi = rdx; call 0x4e77ae0; return rbx
```

`0x4e77ae0` is the #173 forward FDE (943 B).
Differences are 1–2 `call` disp32 low bytes only.

Record 3 — 17-byte wrapper triple
(`0x4e76d00`, `0x4e76c00`, `0x4e76be0`):

```
push rbx; rbx = rdi; rsi = rdx; call 0x4e77e90; return rbx
```

`0x4e77e90` is the 2147-byte FDE immediately after
the forward FDE. Differences are 1–2 `call` disp32
low bytes only.

### Reachability and exclusivity

- Each of the 12 fn targets has exactly 1 relocation
  in all of `.rela.dyn`: its own record slot (entries
  61875–61886, contiguous, immediately after #177's
  head-slot entries 61868–61874).
- Full `.text` objdump census: zero E8 call sites and
  zero E9 jump sites targeting any of the 12
  addresses. (The wrappers' own `call` instructions
  target the shared callees, not the triple members.)
- The record prefixes (`[0, 0, 1]` x 4) have no
  relocations at all: they are pure file values.

### Shared callees (heads only)

| callee | FDE | role here |
|---|---|---|
| `0x4e9a310` | 1421 B | record-0 triple's call target |
| `0x4e8c640` | 487 B | record-1 triple's double call target |
| `0x4e77390` | 1324 B | record-1 triple's tail call target |
| `0x4e77ae0` | 943 B | record-2 triple's call target (#173 forward) |
| `0x4e77e90` | 2147 B | record-3 triple's call target (post-forward FDE) |

No semantics beyond the call shapes above are claimed
for these callees.

## Inferences (separated from observations)

- The "second slot family" is not a second family at
  all: the header (6 slots) and the four records (3
  slots each) form one descriptor region of 0x118
  bytes, and the builder's pairs are the consumer
  link between the header world (#177) and the record
  world (this packet).
- The triple-clone shape — same body modulo
  addressing, three copies per record — suggests the
  records are instantiations of one template, but the
  template itself (what generates the three copies) is
  not identified here.
- Because no code calls the twelve functions
  directly, any dispatch through them must go through
  the table slots (or through the builder's pair
  struct, whose consumer is not traced here).

## Limitations

- The "no direct call" census rests on the full
  `.text` objdump census (call/jump target comment
  scan); the generator verifies recorded instruction
  bytes but does not disassemble.
- The shared callees are characterized by FDE size
  and call shape only; their bodies are not analyzed.
- The `+0x118` array is reported only as a boundary:
  its entry shape (0x18 bytes) is observed, its
  meaning is not claimed.
- Static analysis only; no node execution, so no
  runtime values beyond the statically forced
  relocation values and file bytes are claimed.

## Reproduce

Target: node #94 only (91,774,280 bytes, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
Static analysis only; the node binary is never executed.

Code address A maps to file offset A − 0x1000 (`.text`);
`.data.rel.ro` uses VA − 0x2000; `.rela.dyn` entries
are 24 bytes at file offset `0x6bc0`. The generator
fails loudly on any digest, relocation, prefix, or
twin-difference mismatch.

```sh
# record slots (relocations)
readelf -r -W artifacts/node/94/hl-node | grep -E "574be90|574be98|574bea0|574bec0|574bec8|574bed0|574bef0|574bef8|574bf00|574bf20|574bf28|574bf30"
# record-0 triple + record-1 triple
objdump -d -M intel --start-address=0x4e76de0 --stop-address=0x4e76e00 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e76b20 --stop-address=0x4e76bb8 \
  artifacts/node/94/hl-node
# wrapper triples
objdump -d -M intel --start-address=0x4e76d20 --stop-address=0x4e76d31 \
  artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x4e76d00 --stop-address=0x4e76d11 \
  artifacts/node/94/hl-node
python3 tools/be20_mid_table.py --out /tmp/bmt
diff -r /tmp/bmt research/work-items/RE-004-be20-mid-table-94 \
  --exclude=README.md --exclude=MANIFEST.sha256
```

Deterministic regeneration (the generator writes only to --out):

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/be20_mid_table.py --out /tmp/a
PYTHONHASHSEED=99 TZ=Asia/Seoul python3 tools/be20_mid_table.py --out /tmp/b
diff -r /tmp/a /tmp/b   # exit 0
```

## Next question

- What is the `+0x118` array (0x18-byte entries:
  string + 114/100 + packed value) — a location table
  for the descriptor region, or the next record's
  header?
- Who consumes the builder's pair struct — i.e. who
  dispatches through these twelve table slots, and
  with what arguments?
- What do the shared callees (`0x4e9a310`,
  `0x4e8c640`, `0x4e77390`, `0x4e77e90`) do beyond
  their heads — in particular, what does the
  record-1 triple's tag-5 branch select between?

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — node binding, layout, records, relocations,
  triple diffs, census, shared callees, counts
- `records.tsv` — 4 rows, one per record
- `triples.tsv` — 12 rows, one per fn
- `segments.txt` — 16 rows: 16 claim segments (750 bytes),
  each with start..end, length == end − start, file offset,
  and SHA-256
- `MANIFEST.sha256` — digests of the 5 files above
