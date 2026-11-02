# RE-001: map node #94 WAL logical-record reader 0x51618e0

- Component ID: RE-001 (#94 function map), WAL log reader
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json; local copy `work/hl-node-94.bin`, hash verified to match)
- Source commit / reference commit: upstream main `e5c9b643` at submission time
- Claim status: observation for every branch condition, jump-table target,
  report string and call shape below; inference for the mode byte's enum
  names and for the +0x58 snapshot's role (both flagged in records.json)
- Scope included and excluded: the whole 2620-byte window 0x51618e0..0x516231c
  (both decode call sites, both switch tables, all fragment arms, the
  SetCompressionType arm, both error-continuation loops, the prologue).
  Excluded, callee-only: the physical-record decode 0x5161400 (PR #1848),
  the corruption reporter 0x5160f90, the compression-body parser 0x5161850,
  the detail-string builder 0x542f040, and the stream/transform callees
  0x543b020 / 0x543bde0 / 0x543be50 / 0x543bed0 / 0x543dc30. Their call
  shapes and the parser's effects are pinned; their internals are not.

## Bounded question

How does node #94 assemble one logical WAL record from physical records:
which loop runs for which mode byte, how fragments accumulate, what the
SetCompressionType arm accepts, and where each error code returns, reports,
or continues?

## Reproduce

From the repository root, with the digest-verified binary at
`work/hl-node-94.bin`:

```
objdump -d --start-address=0x51618e0 --stop-address=0x516231c work/hl-node-94.bin
python3 research/work-items/RE-001-logical-record-reader-94/export_excerpts.py
python3 research/work-items/RE-001-logical-record-reader-94/verify.py
python3 -m pytest tests/test_logical_record_reader.py -q
```

Note: `endbr64` and the other instruction mnemonics in the excerpt files
are genuine instructions present in the target binary, not placeholders.
Instruction-level detail lives only in those verbatim excerpts; the JSON
in this packet holds semantic records, never a per-instruction list.
The objdump header spells the binary path exactly as given, so the
excerpts must be regenerated from the repository root with the relative
path, as `export_excerpts.py` does.

## Evidence

Window: FDE `0x006352d0 pc=00000000051618e0..0x516231c`, 2620 bytes,
0xb8-byte frame, canary `fs:0x28` at `rsp+0xa8`. Arguments: reader in
rdi, out slice in rsi, accumulator string in rdx, mode byte in rcx's
low byte, nullable transform out-pointer in r8. The decode interface
(0x5161400) is called from 0x51619c6 (skip loop) and 0x5161ec9 (other
loop) with the fragment slice at stack `rsp+0x40`, the remaining-size
out value at `rsp+0x38`, and the transform out-pointer passed through.

Two 16-entry switch tables: base 0x7ee048 for the skip loop (mode 3),
base 0x7ee088 for the other loop. Both map codes 1/5 to the full arm,
2/6 to first, 3/7 to middle, 4/8 to last, 9 to compression, and share
the full arm at 0x5161a50; the remaining arms differ only in their
error continuation (see records.json for every target).

Fragment assembly: full returns the fragment slice itself; first
replaces the accumulator and records the loop-head snapshot
(`reader +0x60 - reader +0x40`) as the first-snapshot; middle appends
with the `0x3fffffffffffffff` cap check (overflow throws length_error);
last appends, returns the accumulator contents, and stores the
first-snapshot as the success offset (`reader +0x58`). A first or full
record arriving while a fragment is open reports "partial record
without end(2)/(1)" when the accumulator is non-empty; the first arm
also resets the stream object (called even with a null object; that
callee guards null). Middle/last without an open fragment report
"missing start of fragmented record(1)/(2)" and loop.

SetCompressionType arm (code 9): reports (non-fatally) "read multiple
SetCompressionType records" when `+0x73` is set and "SetCompressionType
not the first record" when `+0x71` is set, then clears the accumulator,
stores the current snapshot to `+0x58`, and parses. Tags 0 and 7 go
straight to the body parser 0x5161850, which sets `+0x73 = 1`,
`+0x72 = tag`, creates the `+0x78` object, and allocates the `+0x80`
buffer. Any other tag, and any body of 3 bytes or fewer, goes through
the detail builder 0x542f040 ("CompressionTypeRecord: <detail>"); that
callee writes its constant argument 2 into the decision byte, so the
arm always reports "could not decode SetCompressionType record" and
loops — the parse branch from the detail path is unreachable in this
binary. The built detail string is freed unread. The compression arm
does not reset the in-fragment flag.

Error policy: mode 3 loops past corruption (reporting checksum and
bad-length errors, silently skipping trailer/log-number records) and
returns only on end-of-data/leftover, or on a truncated record after
the short-final block. The other loop returns on most errors, with the
exact report/clear/loop matrix in records.json — including the
asymmetries: trailer loops while log-number mismatch returns; the
short-final truncated-body report path does not clear the accumulator;
CRC errors loop except when the sticky flag is set with mode 0.

Callers (census: full executable-segment e8/e9 scans plus whole-file
qword scan): exactly 2 direct callers, 0x50ca36d and 0x520b54f, no tail
jumps, one qword reference at file offset 0x188e98 (table entry, role
not pinned). The second caller passes mode 0, a null transform
out-pointer, an empty slice, and an empty accumulator string.

## Implementation and comparison

`tools/logical_record_reader.py` implements the window over a
caller-supplied decode hook (the decode routine is PR #1848's subject
and is not re-implemented here); all other callees are hooks with the
call shapes pinned above. No Rust component is claimed: this VM has no
cargo/rustc, so the model layer is Python, as in the reference
contributor PRs. `tests/test_logical_record_reader.py` pins the
behavior end to end: full and recyclable records, fragmented records,
restarts, unknown codes, every error code in both loops across modes
0/1/2/3 (including the no-clear truncated-body path and the
sticky-flag CRC matrix), the compression arm (tags 0/7/others, short
bodies, double records, mid-fragment compression), the stream and
one-shot transform paths, the append cap, and the packet itself
(verify script, byte-for-byte sampled instructions against a fresh
objdump run and the raw binary, and a corruption control that fails
verification when an excerpt is tampered with).

## Results and limitations

- Checker: `verify.py` reports ALL CHECKS PASSED (excerpts match a
  fresh objdump run, records.json parses with its required keys, the
  four sampled instructions match the binary byte-for-byte).
- Tests: all tests in `tests/test_logical_record_reader.py` pass.
- Not claimed: the mode byte's enum names (inferred recovery-mode
  reading; branch conditions are pinned regardless), the +0x78 hook's
  arity, the +0x58 snapshot's named role, the LSDA cleanup mapping,
  and the internals of any callee listed as callee-only above.
- No gate is requested here; the packet documents one bounded work
  item for review.
- Next question: the enclosing callers' replay loop (0x520b54f's
  function), which drives this reader with mode 0 and consumes the
  out slice — its record-type dispatch is the natural follow-up.
