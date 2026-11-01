# RE-001: node94 generated-name word consumption and byte normalization

This packet recovers a previously opaque preparation dependency at
`0x144ada0`: thread-local buffered-word consumption/refill request selection,
ordered formatter arguments and two callbacks, and a length-preserving copy
that replaces only ASCII space with underscore. It resolves a bounded RE-001
question from the node code; it does not complete a component or milestone.

Prior #1464 binds this provider as a shell-preparation dependency but leaves
its body open. This contribution starts independently from upstream main
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663` and does not depend on that PR.
Affected files are this packet and `tests/test_generated_name.py`. Imports,
component catalogues and progress gates are unchanged.

## Target and extent

- Artifact: Linux x86-64 node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes.
- SHA-256: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Coordinates: ELF virtual addresses, half-open extents; no load slide or
  normalization masks are applied.

| Role (inferred label) | Complete owning FDE extent | Bytes |
| --- | --- | ---: |
| Generated-name provider | 0x144ada0..0x144b14f | 943 |
| Time-value callback | 0x1454ad0..0x1454b18 | 72 |
| Buffered-word callback | 0x15708b0..0x1570900 | 80 |

The explicit comparison denominator is **three complete FDEs / 1,095 bytes**,
not all helpers or the whole node. `records.json` retains body hashes, file
offsets, FDE/CIE/LSDA identity, instruction counts, calls and incoming forms.
GNU and LLVM exports cover every byte; readelf independently reports the FDEs.

The `.text` census qualifies E8 and RIP-relative FF15/FF25 candidates by
complete decode from their owning FDE starts. It finds four incoming calls
through `0x576e9e0`: `0x13cc399`, `0x13e4e68`, `0x144c58f`, `0x37eab00`.
The slot is the only RELATIVE addend equal to this provider. This is an
encoded-form census, not all possible indirect callers or runtime reachability.

## New established observations

- Index <64 consumes the indexed 32-bit word directly; otherwise one of two
  refill requests precedes reading index 0 and storing index 1.
- The refill choice includes signed budget >0 and the **sign bit of a wrapped
  subtraction**, not a generic signed less-than comparison. PROOF.md preserves
  the distinction, including overflow boundary counterexamples.
- The formatter receives the time-like value first and saved word second,
  with descriptor bytes `c0 01 5f c0 00`. One callback requests two stages
  separated by a space code, short-circuiting nonzero low-AL returns. The
  other forwards a DWORD through a ten-byte scratch-buffer helper.
- Both SIMD widths and scalar paths implement exactly byte 0x20 -> 0x5f.
  The copy preserves length and all other bytes. Empty output is `(0,1,0)`;
  a successful positive-length result is `(n,allocated_pointer,n)`.

These are static request/control/data observations under PROOF.md's stated
valid-state and normal-helper assumptions. No exact rendered timestamp or
digits, name uniqueness, randomness quality, filename safety or filesystem
effect is asserted. The body is useful to future reconstruction because the
refill predicate, callback order and normalization are no longer opaque.

## Reproduction and validation

With materialized pinned inputs, GNU binutils, LLVM objdump, Python 3.14.7
and Capstone 5.0.7, run from repository root:

```sh
packet=research/work-items/RE-001-generated-name-94
python3 "$packet/export_disassembly.py"
python3 "$packet/verify.py" --controls
python3 "$packet/coverage.py"
python3 -m unittest tests.test_generated_name -v
make doctor verify test catalogue-check reproduce
(cd "$packet" && shasum -a 256 -c MANIFEST.sha256)
```

The exporter only invokes native disassemblers/readelf on the target as data.
The verifier authenticates one input snapshot and binds 33 selected semantic
instruction spans, 16 RELATIVE addends and five literal/descriptor records.
Its image/export plumbing is adapted from our MIT-authored #1464 packet;
no unlicensed inferred source is copied.

**57 actual-byte corruption controls** bypass whole-image hashes, body hashes
and export guards to exercise the deeper evidence checks: 33 instruction
spans, 16 addends, five literals and three FDE ranges. A separate prologue
mutation outside those spans checks image, body and export guards individually.
Mutations occur in memory and never execute or modify the capture on disk.

The proof checks all 256 byte values, 8,194 partitions for lengths 0..4096,
and 64 subtraction boundary pairs. These finite checks support the static
argument and do not establish runtime equivalence. The four focused tests
cover authentic regeneration, corruptions, independent guards and proof
arithmetic. Exact commands/results and complete repository test inventory
results are retained in `validation.json` and `suite-results.json.gz`.
Local tools: GNU objdump/readelf 2.47.20260726 and LLVM objdump 18.1.4 on
macOS arm64. No captured node/visor, emulator, live endpoint, key, chain
action or paid dataset was used.

## Overlap, limits and next step

`overlap.json` records all-state PR metadata and current-main searches,
all open and closed-unmerged file/available-patch audits, and related merged
work. #1464 references this provider without recovering it. Closed #26 uses
"generated name" only in an explicit unknown. #669 covers shared ChaCha12
machinery, not this consumer; its helper bodies are deliberately not reclaimed.
#521/#1303 cover other consumers of the time provider; #1330/#1439 address
shared formatting requests. Their results are context, not evidence for this
new body's behavior. No competing recovery was found within the recorded audit.

Unknowns include TLS initialization, actual refill/reseed/entropy effects,
complete formatting/digits/padding, allocation and panic contracts, dynamic
formatter callback, reference-count ownership, LSDA cleanup and runtime
behavior. No Rust implementation, full-function equivalence, build identity or
gate completion is claimed. Next close the shared formatting stage contracts
before asserting exact generated-name bytes or filesystem use.

New code/text are independently authored under MIT; binary excerpts retain
their original rights.
