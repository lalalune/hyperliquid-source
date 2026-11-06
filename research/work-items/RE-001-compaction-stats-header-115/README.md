# RE-001: map node #115's compaction-stats table header formatter (0x5eedda0)

Task ID: **RE-001**. Bounded question: what does the node #115
compaction-stats table header formatter (`0x5eedda0`) write into the
caller's buffer, and in what order do its 21 header-row columns come
from the global pair map?

## What this pins

One complete behaviour, end to end — the whole table header block the
big dump caller prints before the per-level data rows:

- **Formatter `0x5eedda0`** writes three lines into the caller's
  character buffer (the big dump caller's stack buffer at rsp+0x4c0),
  each with one `__snprintf_chk` call on a 2000-byte budget:
  1. `"\n** Compaction Stats [<name>] **\n"` (`0x4382dd`), where the
     name is the caller-supplied `*( *(owner+0x788) + 0x08 )`.
  2. The 21-column header row (`0x9572f8`): the caller-supplied label
     (`*(rdx)`, `"Level"` or `"Priority"` in the two observed calls)
     followed by the pair map's SECOND strings (display names) for
     keys 1, 3..21 — `Files Size Score Read(GB) Rn(GB) Rnp1(GB)
     Write(GB) Wnew(GB) Moved(GB) W-Amp Rd(MB/s) Wr(MB/s) Comp(sec)
     CompMergeCPU(sec) Comp(cnt) Avg(sec) KeyIn KeyDrop Rblob(GB)
     Wblob(GB)`. Key 2 (`"CompactedFiles"`) is never read.
  3. A dash line (`"%s\n"`, `0x43616f`) whose dashes are exactly as
     long as the header row (the row snprintf's would-be length,
     including its trailing newline).
- **Column order** is pinned, not assumed: the 13 `map::at` calls pin
  keys 21, 20, 17, 15, 14, 13, 12, 11, 10, 9, 6, 3, 1, and the seven
  inlined lower_bound + equality lookups pin keys 19, 18, 16, 8, 7, 5,
  4 (each loop compares against key−1 with `jle` and the check against
  key with `jg` to the throw at `0x5eee2e8`, so the accepted key is
  exactly the check constant). The 20 stack varargs are pushed in
  reverse order. `verify.py` re-derives the order from `main.txt`.
- **Name lookup**: `name_getter` (`0x5eeb7f0`) is the pair map's
  `map::at` — lower_bound + equality, returns `&pair`, throws
  `__throw_out_of_range("map::at")` on a missing key. Its 13 call
  sites are all inside the formatter. The display names come from the
  static initializer `0x5efbd80` (`derive_names.py` re-derives the
  21-entry pair table from it, first strings `NumFiles` …
  `WblobGB`, second strings `Files` … `Wblob(GB)`).
- **Callers**: exactly two direct calls, both inside the big dump
  caller `0x5ef66e0..0x5ef8049` — `0x5ef674d` (label `"Level"`) and
  `0x5ef712b` (label `"Priority"`), each preceded by a `string_assign`
  of the label literal onto the stack string at rsp+0x2b0. The site
  windows `site-5ef6707.txt` / `site-5ef710a.txt` capture the label
  assign, the argument setup and the call.

The Python model is `tools/compaction_stats_header_115.py`; its tests
are `tests/test_compaction_stats_header_115.py` (13 checks, including
the two observed header blocks pinned literally, the dash-length rule,
the missing-key throw for every looked-up key, the key-2-never-read
case, and a libc `snprintf` replay of all three calls for six
name/label combinations including a 3000-character name that exercises
the 2000-byte cap). `records.json` carries the semantic records and a
spot-check block that `verify.py` rebuilds independently from the
recorded formats, pair table and column order.

## Evidence

- Artifact: node #115, `work/hl-node-115.bin`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (see `provenance/artifacts.json`, `artifacts/node/115/hl-node`).
- Every `*.txt` excerpt is the raw output of
  `objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
  for one whole function (FDE); regenerate them with
  `export_excerpts.py`. The `name_getter` and `initializer` excerpts
  are re-shipped verbatim from PR #3164 (diffed byte-for-byte against
  the source packet). The two site windows are instruction-aligned
  sub-ranges of the big dump caller.
- Mnemonics such as `endbr64` are genuine instructions present in the
  target binary, not placeholders. Instruction-level detail lives only
  in the raw excerpts; `records.json` holds semantic records only.
- `census.py` is the exhaustive direct call / tail-jump census
  (byte-scan of every executable PT_LOAD segment, each kept site
  confirmed against its containing FDE); its committed output is
  `callers.tsv` and `relocations.txt`. The formatter has exactly 2
  direct calls and 0 tail jumps; `name_getter` has exactly 13 calls,
  all inside the formatter; the initializer has 0 direct calls and
  one tail jump at `0x5effdc4`; no pinned routine has a stored qword
  outside `.rela.dyn`.
- `frames.txt` lists the FDE lines for the pinned functions;
  `MANIFEST.sha256` covers every packet file. `verify.py` re-checks
  the artifact digest, the manifest, excerpt regeneration and bytes,
  the FDE lines, the census, the derived pair table, the spot check,
  the model tests, the pinned format/label literals, and the column
  order re-derived from `main.txt`.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make verify` / `make test` / `make catalogue-check` are not runnable
here and no hosted CI result is claimed. The model and packet checks
are the verification that was run; see `verify.py`.

## Corrections made while building this packet

- The first reading of the inlined finds took the loop constant as the
  key (18, 17, 15, 7, 6, 4, 3), which would have duplicated keys 17,
  15, 6, 3 and omitted 19, 16, 8, 5, 4. The loop actually compares
  against key−1 with `jle` (lower_bound(key)) and the check compares
  against key with `jg`, so the accepted key is the check constant:
  the finds pin 19, 18, 16, 8, 7, 5, 4, and the columns are the label
  plus keys 1, 3..21 — matching the RocksDB header layout.
- The first reading of the push sequence took the varargs in push
  order; the stack varargs are in reverse push order, so the column
  order is the reverse of the push order (label first, key 21 last).
- The dash string length is the row snprintf's would-be length
  (uncapped), not the written length: for a truncated row the dashes
  are still built to the full row length (the dash snprintf itself is
  then capped by the remaining budget).

## Unknowns

- What object `*(owner+0x788)` points to and what its `+0x08` char*
  names: the formatter only uses it as the title's `%s`, so the model
  takes the name as an input.
- The big dump caller `0x5ef66e0..0x5ef8049` body is not pinned beyond
  the two site windows; the per-level data-row formatter `0x5eed6f0`
  (called at `0x5ef6b84`, `0x5ef6e09`, `0x5ef70de`, `0x5ef72dd`) is a
  separate candidate, not modelled here.
