# RE-004 be20 location-site FDEs — node #94

## Claim status

**Claimed.** #179's second Next question — which FDEs contain
the 35 panic-Location citation sites, and do the 13
continuation sites share one caller function? — is answered:
the 35 sites fall into exactly 11 `.eh_frame` FDEs, and yes,
all 13 continuation sites plus entry 11's indirect site sit
in one FDE (`0x4e79b00..0x4e7a541`, 2625 bytes), together
with the shared funnel block they all reach. One caller
function, not a cross-function fragment.

- **11 FDEs, 35 sites.** Site counts per FDE are 1/2/1/1/
  14/3/4/1/2/4/2 (in FDE order). Every site's enclosing FDE
  was derived from a full `.eh_frame` record walk (121299
  FDEs, zero overlaps), not from the `.eh_frame_hdr`
  search table — the table's `table_enc` is datarel
  (`0x3b`), so a naive pcrel read of its entries yields
  wrong starts. The record walk is the authority here.
- **The funnel FDE.** All 13 continuation sites
  (`lea` + `jmp` to `0x4e7a4bd`, or fall-through into it,
  or entry 17's `jmp` to `0x4e7a4c6`) and entry 11's
  indirect site (`0x4e7a4ce`) lie in FDE
  `0x4e79b00..0x4e7a541`, as does the funnel block
  itself (`0x4e7a4bd..0x4e7a4e6`: restore `rbx`/`r14`,
  `call [0x576e470]`, `jmp` to `ud2`). The 13 sites'
  `lea`/`jmp` pairs and the funnel are one function's
  code, not 13 callers converging from elsewhere.
- **Multi-FDE entries.** Entries 19, 20, 21 are each cited
  from 3 different FDEs, entry 22 from 4 different FDEs;
  all other entries are cited from exactly 1 FDE each.
  One Location record, several citing functions — the
  observation is the citation spread; the explanation
  (inlining/instantiation) is inference only, unconfirmed.

**Not claimed.** No defect, exploitability, or security
severity is claimed. The rest of each FDE outside the site
cluster and the funnel block is not analyzed (in
particular, only the site cluster at the tail of the
2625-byte funnel FDE is characterized). The runtime
helpers behind the GOT slots are #179's subject, not
re-analyzed here.

## Scope

Included:

- The 35 sites (`sites.tsv`): site, entry, register,
  follow shape, GOT slot or continuation target, plus the
  new enclosing-FDE columns (`fde_start`, `fde_end`).
  The site/entry/reg/follow/target columns reproduce
  #179 `sites.tsv` verbatim (its subject, cited as the
  input table, not re-claimed).
- The 11 enclosing FDEs (`fdes.tsv`): exact extents,
  sizes, site counts, cited entries.
- The funnel block bytes (`segments.txt`): 2 claim
  segments, 34 bytes, 0 anchors.

Excluded:

- The sites' 7-byte `lea` encodings themselves (#179's
  subject — re-verified here as a precondition of the
  assignment, not re-claimed); the FDE extents
  themselves (ranges, not segment bytes — the assignment
  is verified by `.eh_frame` parsing, not by claiming
  whole-function bytes); the Location records
  (`0x574bf38..0x574c1a8` — #179's subject); the
  `0x574c1a8` / `0x574c1c0` post-run objects (#179's
  Next question, untouched); #176's header-0 /
  decoder-out+8 question (untouched); the #157–#180
  subjects; #1543's fixed-eight topic.

## Observations

### The FDE assignment

| FDE | size | sites | entries |
|---|---|---|---|
| `0x4e77ae0..0x4e77e8f` | 943 | 1 | 0 |
| `0x4e77e90..0x4e78653` | 1987 | 2 | 1, 2 |
| `0x4e786a0..0x4e78b7f` | 1247 | 1 | 3 |
| `0x4e798e0..0x4e79afb` | 539 | 1 | 18 |
| `0x4e79b00..0x4e7a541` | 2625 | 14 | 4–17 |
| `0x4e7a550..0x4e7a604` | 180 | 3 | 19, 20, 21 (first sites) |
| `0x4e7a610..0x4e7a833` | 547 | 4 | 19, 20, 21 (second), 22 (first) |
| `0x4e7a990..0x4e7ab3b` | 427 | 1 | 22 (second) |
| `0x4e7ab40..0x4e7ac6b` | 299 | 2 | 23, 24 |
| `0x4e7ae70..0x4e7b0c8` | 600 | 4 | 19, 20, 21, 22 (third) |
| `0x4e7b210..0x4e7b48f` | 639 | 2 | 22 (fourth), 25 |

FDE span total: 10033 bytes (reported, not claimed).
Registers: `rdi` 32, `rcx` 2 (entries 3, 24), `rdx` 1
(entry 0). Follows: indirect 22, `jmp-cont` 12,
`fallthrough-cont` 1. GOT histogram over the 22 indirect
sites: `0x576e118` x9, `0x576e150` x9, `0x576e2e0` x2,
`0x576e468` x1, `0x576e1b0` x1.

### The funnel block anatomy

```
0x4e7a4bd: mov rbx,[rsp]              ; restore
0x4e7a4c1: mov r14,[rsp+0x8]          ; restore
0x4e7a4c6: call [0x576e470]           ; runtime helper
0x4e7a4cc: jmp 0x4e7a4e4              ; -> ud2
0x4e7a4ce: lea rdi,[entry 11]         ; entry 11's site
0x4e7a4d5: mov rbx,[rsp]              ; entry 11's restore
0x4e7a4d9: mov r14,[rsp+0x8]          ; entry 11's restore
0x4e7a4de: call [0x576e150]           ; entry 11's helper
0x4e7a4e4: ud2                        ; shared noreturn tail
```

Claimed segments split around the interleaved entry-11
`lea`: `funnel-head` (`0x4e7a4bd..0x4e7a4ce`, 17 bytes)
and `entry11-follow` (`0x4e7a4d5..0x4e7a4e6`, 17 bytes).
The 7 entry-11 `lea` bytes (`0x4e7a4ce..0x4e7a4d5`) are
explicitly excluded — they are #179's site bytes, and no
prior packet segment-claims them either (verified: the
excluded range overlaps zero prior segment rows).

### Three structural details inside the funnel FDE

- Entry 17 restores inline: `mov rbx,[rsp];
  mov r14,[rsp+0x8]` appear at `0x4e7a45c..0x4e7a465`,
  immediately before entry 17's `lea` at `0x4e7a465` —
  which is why entry 17's `jmp` goes straight to the
  call at `0x4e7a4c6`, skipping the funnel's restores.
- Entry 6 falls through: its `lea` at `0x4e7a4b6` is 7
  bytes, ending exactly at `0x4e7a4bd` — no `jmp` at all.
- Entry 11 is interleaved, not separate: its site and
  follow code sit between the funnel head and the shared
  `ud2`, yet all of it is inside the same FDE. The
  funnel is a block inside one function, not a shared
  out-of-line helper.

### Indirect-call gaps

18 indirect sites call immediately after the `lea`
(gap 0). Four set up arguments first: entry 0
(`mov esi,0xf`, gap 5), entry 3 (`mov edi,1; xor esi;
xor edx`, gap 9), entry 11 (restore pair, gap 9),
entry 24 (register moves, gap 6). The generator checks
the first `ff 15` within 24 bytes after each `lea`
resolves to the recorded GOT slot.

## Inferences (separated from observations)

- The 14-in-one-FDE result means the continuation
  cluster is one function reporting 14 source positions
  (entries 4–17) through one shared noreturn tail — not
  14 callers sharing a helper.
- Entries 19–22 cited from 3–4 FDEs each suggests the
  same source position is reached through inlined or
  instantiated copies of one reporting path, but the
  mechanism (inlining vs monomorphization vs manual
  duplication) is not determined from static evidence.
- The `ud2` shared by the funnel path and entry 11's
  path is consistent with #179's noreturn-helper shape,
  but the helpers' post-call behavior is not analyzed.

## Prior work and overlap

Segment-claim overlap with #157–#180 is zero bytes
(verified programmatically: 169 standard-schema prior
segment rows plus #166's range-format rows plus a
funnel-region mention scan over #157–#165 packets; the
excluded entry-11 `lea` range also overlaps zero prior
segment rows). No anchors: no prior claim is re-cited.
The candidate directory name is absent from live
upstream main (trees API recursive, not truncated).
No competing open PR matched the searches
(be20+site, site+fde, location+fde, citation+fde).

## Verification

- Target: node #94 only (91,774,280 bytes, SHA-256
  3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f).
  Static analysis only; the node binary was never executed.
- Generator (tools/be20_site_fdes.py) verifies the node
  digest and size first, walks all of `.eh_frame`
  (CIE/FDE parse: 121299 FDEs, zero overlaps), checks
  the 11 FDE records by exact range, checks every
  site's 7-byte `lea` encoding with disp32 resolving
  to its entry (`0x574bf38` + 0x18 x entry), checks
  every follow (first `ff 15` within 24 bytes resolving
  to the recorded GOT slot; `eb` rel8 resolving to the
  continuation target; fall-through ending exactly at
  the target), checks each site's enclosing FDE by
  interval membership, checks the funnel bytes, the
  entry-17 inline restore pair, and the entry-11 `lea`
  boundary, then writes only to --out. Regeneration
  in two directories with different PYTHONHASHSEED/TZ
  is byte-identical and matches the packet files
  (README/MANIFEST excluded).
- MANIFEST.sha256: 5/5 OK. Unit tests: 6/6 pass
  (tests/test_be20_site_fdes.py). make doctor:
  analysis_ready true. make verify: exit 0. make
  catalogue-check: exit 0. make test: Ran 448 tests, OK (442
  baseline + 6 new, 0 regressions).
- Reproduce: objdump -d -M intel --start-address=0x4e7a4bd
  --stop-address=0x4e7a4e6 artifacts/node/94/hl-node for
  the funnel block; readelf -wF artifacts/node/94/hl-node
  for the unwind records; code address A maps to file
  offset A - 0x1000.

## Limitations

- The generator verifies recorded instruction bytes but
  does not disassemble; the site census itself is #179's
  (full `.text` objdump census, lea target comment scan).
- The FDE assignment rests on `.eh_frame` records; if
  the binary's unwind data did not match its code
  layout, the assignment would follow the unwind data.
  The `.eh_frame_hdr` shortcut was deliberately avoided
  after it produced wrong starts (datarel table_enc).
- The rest of each FDE outside the site cluster is not
  analyzed; FDE sizes are extents, not characterizations.
- Static analysis only; no node execution, so no runtime
  values beyond the statically forced relocation values
  and file bytes are claimed.

## Next question

- What are the `0x574c1a8` object (`0, 1, 1`) and the
  `0x574c1c0` object (reloc to dispatcher `0x4e7c780`,
  `0`, 100) that follow the location run — the next
  record's header, or unrelated data?
- Who consumes the builder's pair struct — i.e. who
  dispatches through the be20 mid-table slots, and with
  what arguments?
- What does decoder `0x4e84500` write to out+8 on the
  tag==5 path (corrected framing — not a caller stack
  argument; #176's "stack argument" label is wrong)?
- What is the even-path message representation, and what
  do the decoder's two tables (`0x5752878`/`0x57528b0`)
  select between?

## Files

- `README.md` — this file (counts cross-checked against the files below)
- `evidence.json` — node binding, FDE totals, site counts, GOT map, counts
- `sites.tsv` — 35 rows, one per citation site (+ enclosing FDE)
- `fdes.tsv` — 11 rows, one per enclosing FDE
- `segments.txt` — 2 rows: 2 claim segments (34 bytes),
  each with start..end, length == end − start, file offset,
  and SHA-256
- `MANIFEST.sha256` — digests of the 5 files above
