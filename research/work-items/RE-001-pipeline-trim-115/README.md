# RE-001: node #115 pipeline prologue 0x5f884b0 with its trailing-empty-group trim 0x5f6bc20

Task: RE-001. Bounded question: what does the pipeline prologue at
0x5f884b0 do in order, and how does its trim at 0x5f6bc20 decide
the trimmed group count that the prologue then feeds onward?

## Windows

- Trim: 0x5f6bc20..0x5f6bc61 (65 bytes, FDE file offset 0x1004d28,
  length field 0x10, CIE at the .eh_frame start, augmentation "zR",
  no LSDA field). See frames.txt.
- Pipeline prologue: 0x5f884b0..0x5f88544 (148 bytes, FDE file offset
  0x1005f08, length field 0x34, CIE at the .eh_frame start, no LSDA
  field). See frames.txt.
- Binary: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  bound in provenance/artifacts.json as artifacts/node/115/hl-node.
- The `endbr64` at the head of each window is a genuine instruction
  present in the target binary, not a placeholder. Instruction-level
  detail lives only in the whole-function verbatim excerpts in
  excerpts/; the JSON in this packet holds semantic records only.
- The objdump command that produced the excerpts is recorded in
  export_excerpts.py, which regenerates them byte-for-byte.

## Semantics, stated literally

Object fields (offsets from the pipeline object's base):

- +0x10: signed 32-bit group count.
- +0x14: signed 32-bit trimmed group count, written by the trim.
- +0xa98: base pointer of the 24-byte group entries. Each entry's
  begin qword (+0) and end qword (+8) are read; the third qword is
  never read.

Trim (0x5f6bc20), exactly as the native loop runs:

1. Store the signed 32-bit count to +0x14 at once.
2. If count - 1 < 0 (signed 32-bit), i.e. count <= 0, return with
   +0x14 holding count.
3. Otherwise start at the last entry (index count - 1). While the
   entry's begin qword equals its end qword (empty), store that
   index to +0x14 and step to the previous entry; reaching index -1
   returns with +0x14 holding 0. The first non-empty entry ends the
   scan and +0x14 keeps the value last stored.

So +0x14 ends as count when the last group is non-empty, as
(index + 1) of the last non-empty group when trailing groups are
empty, and as 0 when every group is empty. A group whose begin
pointer is past its end pointer is not empty to the native code:
the equality test fails and the scan stops.

Pipeline prologue (0x5f884b0), in native call order (rdi = object,
rsi = arg2, rdx = arg3):

1. call 0x5f6b660(object).
2. call trim(object) -- the trim above.
3. call 0x5f79580(object, arg2, arg3).
4. call 0x5f870a0(object, arg2, arg3).
5. call 0x5f9c7b0(object + 0xd8, object + 0x1a0,
   sign_extend32(trimmed count)) -- the trimmed count is read back
   from +0x14 after the trim, so the trim's result is this call's
   third argument.
6. call 0x5f801f0(object).
7. call 0x5f6bc90(object).
8. If the flag byte at arg2 + 0x193 is nonzero, tail-jump to
   0x5f880b0(object) at once; otherwise call 0x5f6d700(object)
   first and then tail-jump to 0x5f880b0(object).

The callees other than the trim are recorded as call steps with
their argument registers, not modelled; their own semantics are not
claimed here. The pipeline itself is reached only through the tail
jump at 0x5f8857c (site only; the containing wrapper is not
modelled here).

## Census (whole-file scan, reproduced by census.py)

- Trim: exactly 1 direct call (the pipeline's site 0x5f884c9),
  0 tail jumps, 0 stored qwords, 0 RELATIVE addends.
- Pipeline: 0 direct calls, exactly 1 tail jump (site 0x5f8857c),
  0 stored qwords, 0 RELATIVE addends.

## Verification

`python3 research/work-items/RE-001-pipeline-trim-115/verify.py`
checks the digest and its provenance binding, the MANIFEST over
every other packet file, excerpt regeneration byte-for-byte from a
fresh objdump run, gate and extra instructions byte-for-byte
against fresh objdump and the raw binary bytes, the FDE ranges
re-parsed from .eh_frame, the census site lists recomputed by
census.py, and the model tests. The model tests also cover the
packet records. Run the model tests directly with
`python3 tests/test_pipeline_trim_115.py`.

Environment limits, stated honestly: this VM has no cargo/rustc,
no git-lfs and no Ghidra/Java; `make doctor` fails on missing
providers and `make verify` fails on the LFS-pointer artifact here
(both pre-existing). The packet binds to the materialized
work/hl-node-115.bin instead, and the pytest-style test file runs
under plain python3 via its `__main__` runner because pytest is
not installed.
