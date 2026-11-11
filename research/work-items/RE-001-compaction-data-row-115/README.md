# RE-001: map node #115's compaction-stats per-level data-row formatter (0x5eed6f0)

Task ID: **RE-001**. Bounded question: what does the node #115
compaction-stats per-level data-row formatter (`0x5eed6f0`) write into
the caller's buffer for one `map<int, double>`, in what order do its 22
fields come from the map, and which four call sites in the big dump
caller drive it?

## What this pins

One complete behaviour, end to end — the data row the big dump caller
prints for every level, for the Sum aggregate, for the Int aggregate,
and for every priority:

- **Formatter `0x5eed6f0`** writes one row into the caller's character
  buffer (the big dump caller's stack buffer at rsp+0x4c0) with a
  single `__snprintf_chk` call on a 2000-byte budget (`0x5eedc20`,
  format at `0x96c040`):

  `%4s %6d/%-3d %8s %5.1f %8.1f %7.1f %8.1f %9.1f %8.1f %9.1f %5.1f %8.1f %8.1f %9.2f %17.2f %9d %8.3f %7s %6s %9.1f %9.1f\n`

  The 22 fields are the caller-supplied label (`*(rsi)`, the data
  pointer of a `std::string`) followed by the 21 metric values, keys
  1..21 in order: `NumFiles`/`CompactedFiles` as `%6d`/`%-3d`,
  `SizeBytes` as a human-size string, `Score` … `CompMergeCPU` as
  doubles, `CompCount` as `%9d`, `AvgSec` as `%8.3f`, `KeyIn`/`KeyDrop`
  as integer-formatted strings, `RblobGB`/`WblobGB` as doubles.
- **Metric reads** are pinned, not assumed: the 14 `map::at` calls
  (accessor `0x5eebac0`, 14 sites, all inside the formatter) pin keys
  21, 20, 19, 18, 16, 14, 13, 10, 9, 7, 6, 5, 4, 3, and the seven
  inlined lower_bound + equality lookups pin keys 17, 15, 12, 11, 8, 2,
  1 (each loop compares against key−1 with `jle` and the check against
  key with `jg` to a throw block, so the accepted key is exactly the
  check constant). The 8 xmm varargs are keys 4..11 in order; the 13
  stack varargs are pushed in reverse order. `verify.py` re-derives
  the order from `main.txt`.
- **Integer rendering**: keys 1, 2, 16 are truncated to 32-bit int with
  `cvttsd2si` to a 32-bit register (`%eax`/`%edx`); keys 18, 19 are
  truncated to 64-bit long and printed by the integer formatter
  `0x61d0940` (`"%li"` / `"%liK"` / `"%liM"` / `"%liG"` by |n| bands,
  truncating magic division — verified equal to truncating division on
  20000 random values per band); key 3 is converted to an unsigned
  long (plain `cvttsd2si` below 2**63, subtract-2**63 + flip-bit-63 at
  or above it) and printed by the human-size formatter `0x61d0ba0`
  (`"%.2f KB|MB|GB|TB"`, scaling by 1/1024 until below 1024.0).
- **Callers**: exactly four direct calls, all inside the big dump
  caller `0x5ef66e0..0x5ef8049` — `0x5ef6b84` (per-level row, label
  `"L"` + decimal(level)), `0x5ef6e09` (Sum row, label `"Sum"`),
  `0x5ef70de` (aggregate row, label `"Int"`, map built by
  `outer_insert` `0x5ef1630` from the 192-byte struct at rsp+0x1f0),
  `0x5ef72dd` (per-priority row, label from `priority_name`
  `0x5fcebc0`: 0 `Bottom`, 1 `Low`, 2 `High`, 3 `User`, else
  `Invalid`). The site windows capture the label assign / label build,
  the argument setup and the call.
- **Header correspondence**: the header row (PR #3180) has 21 columns
  — label + the pair map's SECOND strings for keys 1, 3..21. The data
  row's `%6d`/`%-3d` pair shares the header's single `"Files"` column;
  the other 19 metric fields sit under the header columns for keys
  3..21. The header row is 192 characters including the newline; a data
  row is 192 when its human-size string fits its `%8s` field.

The Python model is `tools/compaction_data_row_115.py`; its tests are
`tests/test_compaction_data_row_115.py` (13 checks, including the spot
row pinned literally, 200 random metric sets replayed through the C
library's `snprintf`, NaN/inf rendering, the 2000-byte cap with a
3000-character label, the missing-key throw for seven keys, and the
magic-division identities). `records.json` carries the semantic records
and a spot-check block that `verify.py` rebuilds independently from the
recorded format, column order and rendered strings.

## Evidence

- Artifact: node #115, `work/hl-node-115.bin`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (see `provenance/artifacts.json`, `artifacts/node/115/hl-node`).
- Every `*.txt` excerpt is the raw output of
  `objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
  for one whole function (FDE); regenerate them with
  `export_excerpts.py`. The `label_assign` excerpt is re-shipped
  verbatim from PR #3180 (diffed byte-for-byte against the source
  packet). The four site windows are instruction-aligned sub-ranges of
  the big dump caller.
- Mnemonics such as `endbr64` are genuine instructions present in the
  target binary, not placeholders. Instruction-level detail lives only
  in the raw excerpts; `records.json` holds semantic records only.
- `census.py` is the exhaustive direct call / tail-jump census
  (byte-scan of every executable PT_LOAD segment, each kept site
  confirmed against its containing FDE); its committed output is
  `callers.tsv` and `relocations.txt`. The formatter has exactly 4
  direct calls and 0 tail jumps; the accessor has exactly 14 calls,
  all inside the formatter; the human-size formatter has exactly 4
  calls (1 here, 3 in the consumer `0x5eefda0`); the integer formatter
  has 12 calls (2 here, 10 in one other routine); `outer_insert` has
  exactly 4 calls; no pinned routine has a stored qword outside
  `.rela.dyn` and none has a RELATIVE relocation record.
- `frames.txt` lists the FDE lines for the pinned functions;
  `MANIFEST.sha256` covers every packet file. `verify.py` re-checks
  the artifact digest, the manifest, excerpt regeneration and bytes,
  the FDE lines, the census, the spot check, the model tests, the
  pinned format/label literals, and the column order re-derived from
  `main.txt`.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make verify` / `make test` / `make catalogue-check` are not runnable
here and no hosted CI result is claimed. The model and packet checks
are the verification that was run; see `verify.py`.

## Corrections made while building this packet

- The first reading of the push sequence took the varargs in push
  order; the stack varargs are in reverse push order, so the column
  order is the reverse of the push order (label first, key 21 last).
  The same re-derivation caught the register/stack split: the 15
  doubles reach the snprintf as xmm0..xmm7 (keys 4..11) plus seven
  stack varargs (keys 12, 13, 14, 15, 17, 20, 21).
- The first model truncated keys 1, 2 and 16 to 64-bit long; the
  binary uses `cvttsd2si` to a 32-bit register (`%eax`/`%edx`) for
  those three, so out-of-range doubles yield INT32_MIN and values
  outside int32 range print their low 32 bits. The model now uses
  32-bit truncation for exactly those keys.
- The first reading of the inlined finds took the loop constant as the
  key; as in PR #3180, the loop compares against key−1 and the check
  against key, so the finds pin 17, 15, 12, 11, 8, 2, 1.
- The first spot row was hand-computed with two `%9.1f` fields counted
  as 8 wide and the `%7s`/`%6s` fields short; the model and the C
  library agree the row is 193 characters for the sample (the
  human-size string `"117.74 MB"` is 9 characters, one more than its
  `%8s` field), and the pinned spot row is the model/C value.
- CORRECTION to PR #3082's state entry: it placed the human-size
  formatter's fourth call (`0x5eedac6`) "in the sibling formatter
  `0x5eedda0`". The census here proves `0x5eedac6` is inside the row
  formatter `0x5eed6f0..0x5eedd9e`, not the header formatter
  `0x5eedda0`.

## Unknowns

- The 192-byte priority-aggregate struct at rsp+0x1f0 that
  `outer_insert` turns into the Int row's map is computed by the
  vectorized block at `0x5ef6e47..0x5ef7050` (including a ratio `divsd`
  at `0x5ef704c`); its fields are not pinned here.
- The sibling `0x5ef1d60` (FDE `0x5ef1d60..0x5ef1f39`) that builds the
  priority outer map, and the filler `0x5ef1fa0` that rebuilds the
  level outer map, are not pinned beyond their call sites; whether the
  priority map always contains every key the site-4 loop asks for
  (which would make the `node_create` path dead code) is not
  established.
- The Sum and priority create paths call `node_create`, which
  initializes an EMPTY inner map; a row printed from it would throw
  `map::at` on key 21, so those paths either never run in practice or
  abort the dump — not resolved here.
- The second lower_bound walk in the site-4 loop
  (`0x5ef725f..0x5ef729b`) duplicates the first walk's key search; its
  exact role (insert-hint computation for the create path) is
  inferred, not proven.
- The int formatter's 10 other call sites (`0x5ef5314..0x5ef5795`)
  and `priority_name`'s other caller (`0x61d5115`) belong to routines
  not examined here.
- The formatter's buffer is the caller's 2024-byte stack buffer; the
  formatter's own writes never pass offset 2000, but the caller's
  buffer size is inferred from the frame layout (`0xca8 - 0x4c0`), not
  from a stated allocation.
- What object `*(owner+0x788)` points to and what its `+0x08` char*
  names (the header formatter's title argument) is not pinned in this
  packet; the row formatter does not use it.
