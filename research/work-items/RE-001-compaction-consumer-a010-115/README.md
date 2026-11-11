# RE-001: map node #115's fourth stats consumer — per-level compaction stats + summary (0x5efa010)

Task ID: **RE-001**. Bounded question: what does the node #115 fourth
stats consumer (`0x5efa010`) emit into the out map for each compaction
level and in total, and how are its 21 per-level metric values computed?

## What this pins

One complete behaviour, end to end:

- **Filler `0x5ef1fa0`** builds an outer
  `std::map<int, std::map<int, double>>` keyed by level marker: one entry
  per level plus a `Sum` entry (key `-1`). Each inner map holds 21
  per-level compaction metrics (ids 1..21), inserted by **`0x5ef1630`**
  from one 192-byte level struct (owner+0x138 + level*0xc0), the
  per-level element/flagged counts, the `0x5f6c300` sum `S`, the dense
  double, and the filler ratio. The full formula table is in
  `records.json` (`metric_formulas`); the constants are
  `2**-30` (.rodata `0x459c48`), `2**-20` (.rodata `0x459638`) and
  `1e6` (.rodata `0x4599a0`). A level is skipped when its first 16
  bytes are both zero and it has no elements — but its counts still
  join the Sum totals. The Sum node is inserted unconditionally; its
  metrics come from the lane-wise accumulated snapshot with the summed
  totals and dense 0.0.
- **Main `0x5efa010`** walks the outer map and writes, for every
  (level, metric) pair,
  `out["compaction." + label + "." + name] = "%f" % value`, where the
  label is `Sum` for marker -1 else `L` + decimal(marker) and the name
  is the metric's internal name from the global pair map at `0x6503a00`
  (keys 1..21, first strings `NumFiles`, `CompactedFiles`, …,
  `WblobGB` — derived from the static initializer `0x5efbd80` by
  `derive_names.py`). Values use `fmt_pct` (`0x5eec680`, `"%f"`).
  Main then calls the summary consumer and destroys the outer tree.
- **Summary consumer `0x5ef5d40`** writes seven further entries as
  decimal strings: three tag-selected counters
  (`memtable-limit-delays` = owner+0xb8, `l0-file-count-limit-stops` =
  owner+0xd0, `pending-compaction-bytes-stops` = owner+0xe0), two
  ongoing-compaction counters (owner+0xe8, owner+0xf0), and the
  `total-stops` / `total-delays` aggregates.

The Python model is `tools/compaction_consumer_a010_115.py`; its tests
are `tests/test_compaction_consumer_a010_115.py` (22 checks, including
the literal decimal conversion and u64->double fixup against Python's
own `str()`/`float()` on large random samples, the 21 metric formulas
against hand-computed values, and the filler/main/summary behaviour
end to end). `records.json` carries the semantic records and a
70-entry spot-check map that `verify.py` recomputes from the model.

## Evidence

- Artifact: node #115, `work/hl-node-115.bin`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (see `provenance/artifacts.json`, `artifacts/node/115/hl-node`).
- Every `*.txt` excerpt is the raw output of
  `objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
  for one whole function (FDE); regenerate them with
  `export_excerpts.py`. The `fmt_pct`, `map_node_create`,
  `map_find_insert`, `string_move_assign`, `name_join`,
  `name_lookup1`, `name_lookup2` and `initializer` excerpts are
  re-shipped verbatim from PR #3145 (diffed byte-for-byte).
- Mnemonics such as `endbr64` are genuine instructions present in the
  target binary, not placeholders. Instruction-level detail lives only
  in the raw excerpts; `records.json` holds semantic records only.
- `census.py` is the exhaustive direct call / tail-jump census
  (byte-scan of every executable PT_LOAD segment, each kept site
  confirmed against its containing FDE); its committed output is
  `callers.tsv` and `relocations.txt`. Main is called by exactly one
  23-byte forwarding thunk (`0x5efae30`, returns 1); the filler is
  called from main and from the sibling consumer `0x5ef66e0`; the
  summary consumer is called from main, from a 23-byte thunk
  (`0x5ef6220`, returns 1) and from the sibling `0x5ef6280`. The
  inner insert `0x5ef1480` has exactly 21 call sites, all inside
  `0x5ef1630` — one per metric id.
- `frames.txt` lists the FDE lines for the pinned functions;
  `MANIFEST.sha256` covers every packet file. `verify.py` re-checks
  the artifact digest, the manifest, excerpt regeneration and bytes,
  the FDE lines, the census, the derived pair table, the spot check,
  the model tests, and the pinned literals and digit-pair table.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make verify` / `make test` / `make catalogue-check` are not runnable
here and no hosted CI result is claimed. The model and packet checks
are the verification that was run; see `verify.py`.

## Corrections made while building this packet

- Metric 17's else branch is `0.0` (outer_insert.txt `0x5ef19ee`:
  xmm0 is zeroed before the L+0x68 test). An earlier trace draft had
  recorded it as `(double)L+0x00 / 1e6`.
- The summary consumer's tag-selected offsets are owner+0xb8, +0xd0,
  +0xe0 (final.txt `0x5ef5db9`: `mov 0xb8(%rax,%rbx,8)`). An earlier
  trace draft recorded +0xbd0/+0xbe0.
- The Sum node is inserted unconditionally after the per-level loop;
  only its ratio is gated on (owner+0x90 + owner+0x98) != 0.

## Unknowns

- The alternate filler entry (subobject byte +0x5a8 == 2 at
  `0x5ef272a`): its src layout and loop-entry deltas are recorded in
  `records.json` but not modelled; the normal path is modelled.
- The sibling big consumer `0x5ef66e0..0x5ef8049` (calls the filler and
  `0x5ef1630`) and the sibling `0x5ef1d60..0x5ef1f39` (calls
  `0x5ef1630`) are the next candidates, not part of this item.
- The sibling formatter `0x5eedda0` (reads the pair map's SECOND
  strings for its `** Compaction Stats [%s] **` columns) is a separate
  candidate, not modelled here.
