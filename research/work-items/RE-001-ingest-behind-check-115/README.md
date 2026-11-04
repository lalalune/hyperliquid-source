# RE-001: node #115 ingest-behind admission gate 0x5ebd1c0

## Task and bounded question

RE-001 (#115 function map, docs/TASKS.md: "Decode FDE ranges, account for
duplicates/missing functions, validate #115 entrypoints and xrefs with
digest-bound records"). Bounded question: what does the 355-byte function
at 0x5ebd1c0 decide, end to end, before a file is ingested behind the
bottommost level — which check runs first, which records are scanned,
which records are skipped, and what Status does the caller get back in
each outcome?

## Windows

* Gate 0x5ebd1c0..0x5ebd323 (355 bytes, FDE range as shown in
  frames.txt). The main window of this item.
* Wrapper 0x5ebd130..0x5ebd1b8 (136 bytes). The selector-inversion
  wrapper pinned by the earlier RE-001 wrapper item; referenced here,
  not re-claimed. Its semantics are restated in the model so this
  packet is self-contained.
* Reporter 0x61cf670..0x61cf767 (247 bytes). The shared Status builder
  used by 847 direct call sites across the binary; modelled in full
  here because the gate's observable output is the Status contents.
  The excerpt covers the full FDE range, including the allocation
  landing pad at the end of the range.

All three windows are bound to one artifact: work/hl-node-115.bin,
SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
which hashes exactly to the provenance/artifacts.json entry for
artifacts/node/115/hl-node.

## Semantics, stated literally

The gate takes a Status object, a source object and a third argument,
and returns the Status object:

1. Read the signed 32-bit count at struct+0x650, where struct is the
   qword at source+0x40. Read the link object at struct+0x30.
2. Call the wrapper with (source, third argument, count - 1 with
   32-bit wrap). The wrapper returns 1 at once when the index is 0
   (no selector call, no field read); otherwise it returns the
   selector result with its low bit flipped, where the selector is
   called with (link+0x40, index, record 1, record 2) and the records
   are (third+0x20, third+0x28 - 8 wrapping) and (third+0x40,
   third+0x48 - 8 wrapping). The selector's dispatch callee is not
   modelled, so the selector stays an oracle in the model.
3. Wrapper result zero: build an error Status with code 4 and the
   bottommost-level message (67 bytes at 0x966bf0) and return. The
   third argument's +0x390 field is not written on this path.
4. Otherwise re-read the count (assumed stable, see below). Count
   <= 1: store count - 1 (first read) at third+0x390, zero the
   written Status bytes, return an OK Status.
5. Otherwise scan the 24-byte records at link+0xad8, indices
   0..count-2 (the last record is never scanned). Each record's first
   two qwords are the begin and end of an 8-byte-element array; for
   each element, read the qword at element+0x18. The first element
   whose field is zero stops the scan: build an error Status with
   code 4 and the upper-levels message (118 bytes at 0x958548) and
   return, again without writing +0x390.
6. No zero field found: same clean outcome as step 4.

The Status builder writes the code byte at +0, byte1 at +1, byte2
at +2, a zero word at +3, a zero byte at +5, and the message pointer
at +8; the message is the first slice, plus ": " plus the second
slice only when the second slice is non-empty. In both gate paths
the second slice has length 0, so the message is exactly the one
slice. The previous message buffer is released when non-null. Status
bytes 6-7 are written by neither the clean path nor the builder and
are outside this model.

## Attribution split: what is node-side and what is shared

* The gate (wrapper consultation, group-record scan with the last
  record skipped, outcome-to-message mapping) is the node-side claim
  of this item: the wrapper, the selector and the group-record array
  are the node's own structures.
* The reporter is shared code of dependency style, not node-specific
  logic: one constructor used by 847 direct call sites across the
  binary. It is tagged as such in records.json and modelled in full
  only because the gate's observable output is the Status contents.
  Its exact upstream provenance is not verified here and is not
  claimed.
* The two diagnostic strings are worded as the public RocksDB
  ingest_behind diagnostics. The exact upstream revision is not
  verified here and is not claimed; this item claims the gate logic
  that selects between them, not the strings on their own.

## Why this is node-side work, not a library claim

The strings and the Status layout resemble shared storage-engine
wording, but the gate logic around them is node-side: the wrapper, the
selector, the group-record array and the count field are the node's
own structures (the same object graph the earlier RE-001 group,
predicate and filter-pass items map). This item claims that gate
logic, not the strings on their own.

## Evidence

* `gate.txt`, `wrapper.txt`, `reporter.txt`: whole-function excerpts,
  verbatim as objdump emitted them, regenerated by
  `export_excerpts.py`. The instruction text in those files is the
  target binary's own disassembly: tokens that look generic (such as
  the function-entry instruction) are genuine instructions present in
  the binary, not placeholders. The checker re-verifies the excerpts
  byte-for-byte against a fresh objdump run.
* `frames.txt`: the three FDE blocks. The gate and wrapper use the
  plain CIE; the reporter uses a different CIE with augmentation
  data `15 68 01 ff`, consistent with its landing pad.
* `records.json`: semantic records only. Instruction-level detail
  lives only in the excerpt text files, never as a per-instruction
  list in the JSON.
* `callers.tsv` + `census.py`: the reference census, reproduced by
  the committed script from a full disassembly pass: gate exactly 1
  direct call (site 0x5ec97ab), wrapper exactly 3 direct calls
  (0x5ebd203, 0x5ec9076, 0x5ec9394 — the same three the wrapper item
  reported), reporter 847 direct calls including the gate's own site
  0x5ebd299; no tail jumps, no stored qwords and no RELATIVE
  addends for any window (see `relocations.txt`).
* `verify.py`: the checker. It confirms the digest, the provenance
  entry, the manifest, excerpt regeneration byte-for-byte, the gate
  and extra instructions byte-for-byte against a fresh objdump run
  and the raw binary, the FDE ranges, the census consistency
  (TSV count, the gate's site, spot checks), and the model tests.

Regeneration commands (from the repository root):

```
objdump -d --start-address=0x5ebd1c0 --stop-address=0x5ebd323 work/hl-node-115.bin
objdump -d --start-address=0x5ebd130 --stop-address=0x5ebd1b8 work/hl-node-115.bin
objdump -d --start-address=0x61cf670 --stop-address=0x61cf767 work/hl-node-115.bin
python3 research/work-items/RE-001-ingest-behind-check-115/export_excerpts.py
python3 research/work-items/RE-001-ingest-behind-check-115/census.py
python3 research/work-items/RE-001-ingest-behind-check-115/verify.py
python3 tests/test_ingest_behind_check_115.py
```

## Model and tests

`tools/ingest_behind_check_115.py` implements the gate, the wrapper
restatement and the Status builder; `tests/test_ingest_behind_check_115.py`
covers both report paths, both clean paths, the index-0 fast path
(selector never called), the index -1 case, the unscanned last
record, empty inner ranges, the ": " join rule of the builder, and
the guards. 14 checks pass under plain python3 (pytest is not
installed on this VM).

## Assumptions and limits, stated explicitly

* The count is assumed stable across the gate's two reads.
* The caller supplies at least count - 1 records; shorter arrays and
  null element pointers are rejected by the model (native code would
  read out of bounds / fault).
* The selector's dispatch callee is not claimed; the selector is an
  oracle callable in the model.
* Status bytes 6-7 are not claimed.
* Environment limits: no cargo/rustc, no git-lfs, no Ghidra/Java on
  this VM. The pre-existing `make verify` / `make test` failures on
  the LFS-pointer artifacts are unrelated to this change and are not
  re-claimed here; the packet binds to the materialized
  work/hl-node-115.bin instead.
