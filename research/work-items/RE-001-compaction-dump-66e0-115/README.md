# RE-001: compaction-stats dump 0x5ef66e0 (node #115)

## Task and bounded question

Task **RE-001**. Bounded question: what does the node #115
compaction-stats dump routine `0x5ef66e0` emit end-to-end, and how does
each of its sections contribute to the output?

This is the capstone of the compaction-stats family: the routine that
calls the header formatter (#3180), the per-level data-row formatter
(#3189), the filler (#3164), the snapshot consumer (#3082) and the
final/summary consumer (#3164), and assembles their rows into one dump
string. The routine itself, its two siblings, and the small helpers
they share are pinned here; the formatters and consumers are re-shipped
byte-identical from their own PRs (see "Re-shipped excerpts").

## Artifact

Node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(size 105896032), present locally as `work/hl-node-115.bin`.

## What the routine emits

`dump(owner=rdi, update=esi: bool, out=rsi: std::string*)`, FDE
`0x5ef66e0..0x5ef8049`, frame `sub $0xca8,%rsp`. In order:

1. **Level header** — label "Level", header formatter `0x5eedda0`.
2. **Filler call** — `0x5ef1fa0` fills the outer
   `map<int, map<int,double>>` and the 188-byte snapshot.
3. **Per-level rows** — for each level `i` present in the outer map:
   label `"L<i>"` (digit-pair-table decimal conversion), data-row
   formatter `0x5eed6f0`.
4. **Sum row** — key `-1`, label "Sum".
5. **Int aggregate row** — lane-wise (filler snapshot − previous
   snapshot), ratio `(agg+0x30+agg+0x28)/(1 + flush_interval +
   addfile_interval)`.
6. **Priority header** — label "Priority", header formatter.
7. **Sibling `0x5ef1d60`** — fills the per-priority map.
8. **Per-priority rows** — `priority_name(p)` assigns
   Bottom/Low/High/User/Invalid into the label, data-row formatter.
9. **Blob totals** — `"\nBlob file count: %zu, total size: %.1f GB,
   garbage size: %.1f GB, space amp: %.1f\n\n"`.
10. **Uptime** — virtual call at slot `+0x98` of `*(owner+0x780)`;
    `"Uptime(secs): %.1f total, %.1f interval\n"`.
11. **Flush/AddFile lines** — five `snprintf` lines (GB and count
    forms). Note: each `%lu` section does `sub $0x8,%rsp` first, so
    the literal `0x60/0x68/0x70(%rsp)` reads are frame
    `+0x68/+0x70/+0x78`, i.e. `owner+0xa0/+0xa8/+0xb0`.
12. **Compaction lines** — cumulative and interval lines over the
    level array (`owner+0x138`, 192-byte structs); MB/s divisors are
    `max(uptime, 0.001)`.
13. **Update branch 1** — when `update` is true, store the new
    compaction sums at `owner+0x6e8/0x6f0/0x6f8`.
14. **Sibling `0x5ef6280`** — the "Write Stall" block; also returns
    the stall sum (parse of "total-stops" + "total-delays").
15. **Update branch 2** — when `update` is true, copy the filler
    snapshot and the flush/addfile/uptime/stall counters into
    `owner+0x618..0x720`.
16. **Snapshot-consumer section** — when `owner+0x128` is non-null,
    lock, copy the snapshot, call `0x5eefda0`, append.
17. **Cleanup** — dispose strings, free both maps, canary check, ret.

The full section map, the filler semantics, the sibling semantics,
the 21 metric fields, the format strings and the owner layout are in
`records.json`. The model is in
`tools/compaction_dump_66e0_115.py`; its tests are in
`tests/test_compaction_dump_66e0_115.py`.

## Correction to open PR #3164

#3164's `ratio_for_level` claims "0.0 for level 0". That is wrong. A
fresh objdump of filler `0x5ef22a2..0x5ef2329` shows the branch at
`0x5ef22a2` (`test %edx,%edx; je 0x5ef22ee`) skips **only** the reload
of the denominator from `L+0x20+L+0x10`; `rax` remains `rsp+0x48` =
`owner+0x90 + owner+0x98`, the division still runs when that sum is
nonzero, and the ratio slot is not overwritten before the
`outer_insert` call at `0x5ef23b4`. So the level-0 ratio is
`(L0+0x30 + L0+0x28) / (owner+0x90 + owner+0x98)` when the denominator
is nonzero, else 0.0. The model in this PR implements the corrected
rule and tests it explicitly.

## Evidence

- `main.txt` — whole-function verbatim objdump excerpt of the dump
  routine (`0x5ef66e0..0x5ef8049`).
- `filler.txt`, `sibling_1d60.txt`, `sibling_6280.txt` — the filler
  and the two siblings, whole-function.
- `insert_170.txt`, `insert_a0.txt`, `lower_bound_db.txt`,
  `lower_bound_f20.txt`, `tree_free_cc0.txt`, `tree_free_510.txt`,
  `tree_free_590.txt`, `str_assign.txt`, `str_b20.txt`,
  `getter_3570.txt`, `sum_s.txt`, `sum_vec.txt`, `parse_u64.txt`,
  `key_total_stops.txt`, `key_total_delays.txt`,
  `map_find_insert.txt`, `inner_insert.txt`, `str_assign_lit.txt`,
  `tree_copy.txt` — the helpers the routine and its callees use,
  whole-function.
- `header_formatter.txt`, `data_row_formatter.txt`,
  `outer_insert.txt`, `snapshot_consumer.txt`, `final.txt`,
  `priority_name.txt` — re-shipped byte-identical from PRs #3180,
  #3189, #3082 and #3164 (see below).
- `frames.txt` — the 29 FDE lines from
  `readelf --debug-dump=frames-interp`.
- `callers.tsv`, `relocations.txt` — the exhaustive direct-call /
  tail-jump census (see `census.py`).
- `records.json` — semantic records only: no per-instruction mnemonic
  list. Instruction-level detail lives only in the raw excerpts.
- `verify.py` — the self-check (`python3
  research/work-items/RE-001-compaction-dump-66e0-115/verify.py`).
- `export_excerpts.py` — regenerates every excerpt with the objdump
  command below; `census.py` regenerates the census.

Mnemonics such as `endbr64` in the excerpts are genuine instructions
present in the target binary, not placeholders: every excerpt is the
raw output of

    objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin

with no post-processing, and `verify.py` re-runs that command and
compares byte-for-byte, and checks every instruction line's bytes
against the raw binary.

## Re-shipped excerpts

These eight excerpts were copied verbatim from the cited open PRs and
diffed byte-for-byte against a fresh objdump run of the same range
before committing:

| file | range | source |
| --- | --- | --- |
| `header_formatter.txt` | `0x5eedda0..0x5eee30c` | #3180 `RE-001-compaction-stats-header-115/main.txt` |
| `str_assign.txt` | `0x5eebd00..0x5eebde3` | #3180 `RE-001-compaction-stats-header-115/string_assign.txt` |
| `data_row_formatter.txt` | `0x5eed6f0..0x5eedd9e` | #3189 `RE-001-compaction-data-row-115/main.txt` |
| `outer_insert.txt` | `0x5ef1630..0x5ef1d33` | #3189 `RE-001-compaction-data-row-115/outer_insert.txt` |
| `priority_name.txt` | `0x5fcebc0..0x5fcec41` | #3189 `RE-001-compaction-data-row-115/priority_name.txt` |
| `insert_a0.txt` | `0x5eed0a0..0x5eed161` | #3189 `RE-001-compaction-data-row-115/node_create.txt` |
| `snapshot_consumer.txt` | `0x5eefda0..0x5ef0360` | #3082 `RE-001-snapshot-consumer-efda0-115/main.txt` |
| `final.txt` | `0x5ef5d40..0x5ef621d` | #3164 `RE-001-compaction-consumer-a010-115/final.txt` |

## Verification

`python3 research/work-items/RE-001-compaction-dump-66e0-115/verify.py`
checks, in order: the artifact digest against
`provenance/artifacts.json`; `MANIFEST.sha256`; byte-for-byte excerpt
regeneration from a fresh objdump; every instruction line's bytes
against the raw binary; every `frames.txt` line against a fresh
readelf dump; census reproduction; `records.json` plus the digit-pair
table build parsed from `main.txt` (both builds must agree with the
recorded chunks/store offsets and assemble to the model's table), a
three-instruction spot check (`random.Random(66)`) byte-for-byte
against a fresh objdump, and the model reproducing the level-0 ratio
correction and a blob line rendered independently via the C library;
the model tests; the pinned literals; and the section order re-derived
from `main.txt`.

## Unknowns

- Alternate filler path when the byte at `(owner+0x788)+0x5a8 == 2`
  (see `records.json`).
- The concrete callee behind the virtual-call slot `+0x98` of
  `*(owner+0x780)`.
- The `0x141dd75fff` snapshot-consumer append guard.
- `owner+0x700` is read here but never written here.
- The three tiny wrapper callers of the dump routine and the tiny
  thunk caller of sibling `0x5ef6280` are recorded, not modelled.
- The `strtoull` error paths in `parse_u64` are modelled only on the
  well-formed path.

## Environment limits

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so `make
verify` / `make test` / `make catalogue-check` cannot be run here.
The packet's own `verify.py` and the model tests are the verification
run, and they pass. Hosted CI results are not claimed.
