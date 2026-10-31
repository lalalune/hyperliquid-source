# RE-001 / foundation: five string-result output wrappers

Question: what words reach the selected normal-return output of the five
reference-labelled string-result wrappers, and do they retain all error payloads?
Scope: `tools/string_result_wrappers.py`, focused controls and this packet.
This is partial static mapping, not a Rust implementation or completed gate.

Target: node94 `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
The unlicensed can1357-hl reference revision
`999556f6e0a474b8312db96ec3149e1c44e97c23`, `base/u.rs`, provides names and
five seeds only; no implementation is copied. Its generic `Timed<Result<...>>`
adapter does not itself establish the binary output layout or retained errors.

## Observations

All coordinates are ELF virtual addresses; no masks. The five real FDE owners
start at `0x28bf690`, `0x28bfbd0`, `0x28c0110`, `0x28c0650`, `0x28c0b90`.
Their complete exports total **6,687 bytes / 1,460 instructions**. Each has 292
instructions; the second has 1,339 bytes, the others 1,337. Actual FDE/CIE,
full-body hashes, selected boundaries and eight-entry relative dispatch tables
are preserved. This is an export denominator, not full semantic coverage.

For each selected output arm:

- A dword tag at stack `+0x40` equal to 8 takes the copy arm. The three words
  from stack `+0x48/+0x50/+0x58` are copied to output `+0/+8/+0x10`.
- For the declared other tags 0..7, the output words are set to **(0,1,0)**.
  The original local payload is then dispatched through an eight-entry table.
- Table entries 0,1,2,4,6 directly join the epilogue. Entry 3 loads the word
  at stack `+0x18` and tests it; entry 7 loads an address at stack `+0x18`
  and the immediate size 16. Entry 5 takes a call to `0x283a460` after
  clearing a local flag. Their complete effect/ownership types are unclosed.
- Both selected output arms converge on returning the original output pointer
  in RAX. No timing fields are appended by these selected output stores.

The exact per-owner compare/copy/collapse/join/table addresses and table targets
are in `records.json`; all five related copies belong to this one packet.
The selected normal-return arm is distinct from the TLS state-bracket work in
#571: this packet neither recovers nor counts the runtime bracket again.

## Inferences and limits

The words resemble a String-like header and an empty-header normalization.
Original Rust String/Result/Timed ABI, error discriminant meanings, decoder
semantics, actual tag reachability, ownership/drop effects, timing/logging and
TLS/unwind behavior remain unknown. Tags 0..8 are the declared local test domain;
no out-of-range table access or full decoder execution is attempted. This packet
does not establish a general-purpose parser or reconstructed error type.

Before: five reference seeds and a generic adapter narrative. After: exact
conditional output stores and cleanup dispatch coordinates bound to captured
bytes. No imported source, component gate, runtime state or captured executable
is modified or executed. Next question: close the decoder and three cleanup
arms before assigning a typed result and ownership contract.

## Reproduction and controls

Python 3.12.14, stdlib static ELF parsing. Optional export: Capstone 5.0.6,
x86-64 Intel, complete contiguous disassembly; no native instructions execute.

```
python tools/string_result_wrappers.py --out research/work-items/RE-001-string-result-wrappers-94/records.json
python research/work-items/RE-001-string-result-wrappers-94/export_disassembly.py
python -m unittest tests.test_string_result_wrappers -v
```

Six focused methods pass in 11.025 seconds. Selected actual load/store arms are
interpreted for 225 owner/tag/payload cases, including zero and high-bit words.
Changing the real collapse immediate from 1 to 2 changes the interpreted output
to (0,2,0), and the binding verifier rejects it. Actual-capture controls also
change five tag guards, payload operands, every dispatch-table entry, helper
calls, FDE extents and target identity. These controls do not substitute for a
complete decoder, runtime or native equivalence test.

Required Makefile commands were run directly because Make is unavailable.
Full discovery: **363 tests in 119.632 seconds; 7 failures, 16 errors, 21
skips**. All six new methods pass. Existing Windows newline/POSIX-path and
native-tool constraints remain failures; this branch excludes unmerged #227.
Doctor reports missing prerequisites. Artifact verification passes eight
size/digest checks before missing GPG prevents signature verification. Imports
reject the Windows reference checkout; catalogue-check rejects backslash paths.
Reproduce stops at artifact verification. Full-suite, signature, hosted-CI and
native-equivalence success are not claimed. Raw logs are retained in ignored work.
