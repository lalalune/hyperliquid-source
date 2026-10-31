# RE-014: independently bind the kind-5 graph in node115

The node94 packet deliberately did not transfer its results to node115.
This bounded follow-up compares the complete instruction and read-only
dependency windows of the same reader question. It does not execute either
capture or present node94 fixture results as node115 measurements.

Node94: SHA256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
91,774,280 bytes. Node115: SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105,896,032 bytes. Base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
Both identities are checked before creating output. All coordinates below
are linked ELF virtual addresses resolved through their actual sections.

| Observed role | Node94 FDE | Node115 FDEs that pass |
| --- | --- | --- |
| reader | 0x466dad0..0x466dc0c | 0x5822710..0x582284c |
| little-endian wrapper | 0x466be70..0x466bf55 | 0x2cd7bb0..0x2cd7c95 and 0x5821340..0x5821425 |
| local error builder | 0x466dac0..0x466dace | 0x5822700..0x582270e |

## Discovery and denominator

Search the complete node115 text bytes for each selected node94 function's
first24 bytes (all14 for the error builder), retaining only actual FDE
starts. This deterministic prefix census yields eight candidates: three
readers, four wrappers and one error builder. Every candidate is independently
decoded over its full FDE by GNU and LLVM and bound back to actual file bytes.
No symbol name, nearby label or prefix match is accepted as correspondence.

Four candidates pass the complete comparison and four lookalikes fail.
Reader0x5822490 has a different full extent. Reader0x58225c0 differs in scalar
bytes; wrappers0x2cd7ac0 and0x5821250 call that excluded sibling. These are
observed differences, not recovered Rust source-type names. The two accepted
wrappers remain separate copies; no unique caller or source owner is inferred.

There are **238 paired instruction records / 788 paired code bytes** across
the four accepted pairs. Node94's one229-byte wrapper participates twice;
its unique three-function window remains559 bytes /169 instructions. The
selected node115 union is788 bytes /238 instructions. This is an explicit
finite comparison denominator, not coverage of the node, all equivalent
implementations or all callers.

## Exact comparison and dependencies

Every instruction boundary, operation, register, scalar literal and non-RIP
machine byte compares exactly. Local branch destinations must be instruction
starts in the same FDE and have identical function-relative offsets. The only
abstracted machine bytes are each decoded RIP operand's final signed rel32
field, independently recomputed against its actual resolved address. Unknown
RIP dependencies, direct/register calls and unclosed callees are rejected.

For a table reference, all16 bytes must lie in rodata. Each signed entry is
resolved against the real table base, must land at an instruction start in
its own FDE, and must have the same ordered destination offsets as node94.
The three node115 tables are0x935c34,0x60be9c and0x935bec. Their raw bytes and
all destinations are retained. No table entry is ignored by normalization.

Every ff15 slot must have a real RELATIVE relocation to the independently
compared reader or error-builder FDE. Node115 reader slot0x64e7f80 resolves
to0x5822710. Error slots0x64e7f78 and0x64e7f88 both resolve to0x5822700.
The wrapper at0x2cd7bb0 uses0x64e7f88; the wrapper at0x5821340 and the reader
use0x64e7f78. This alias difference is recorded per reference; it is not
collapsed into a claim that GOT layout or runtime mutation behavior is equal.

## Controls and reproduction

Five actual node115 mutations are checked with fresh native instruction decodes
and dependency parsing below the separate public whole-image identity gate:
kind literal5 to4, two table entries exchanged,
an error RELATIVE addend redirected to the excluded sibling, a table RIP
reference redirected to the sibling table, and a local branch displacement
byte changed. All five fail the semantic/byte/dependency comparison. Exact
file offsets, before/after bytes, mutant digests and rejection reasons are
retained in observations.json. These mutants also have the wrong full-image
digest; only the explicit lower-level controls bypass that admission gate.

The six focused tests check the real denominator, rejected lookalikes, all
five semantic controls, distinct slot aliases, wrong-image admission and
refusal to overwrite existing evidence. Ordinary tests skip unavailable
capture/decoder prerequisites. Explicit evidence commands require existing
GNU and LLVM objdump executables and fail if either is missing or misidentified;
they install nothing. Put GNU objdump on PATH and LLVM on PATH as llvm-objdump
or set LLVM_OBJDUMP (this host used /usr/bin/objdump for Apple LLVM17).

```sh
python3 -B tools/kind5_release_drift.py --controls --output work/kind5-drift-fresh
python3 -B -m unittest discover -s tests -p test_kind5_release_drift.py -v
python3 -B research/work-items/RE-005-kind5-reader-94/drift/verify.py --output work/kind5-drift-verified
make doctor verify test catalogue-check reproduce
```

Use new output directories. The verifier checks the full packet manifest and
compared source hashes, then retains a fresh two-decoder/control run in the
chosen output directory. Its observation record must reproduce byte-for-byte;
native display formatting and tool-version strings need not match another
host. Both original native exports and actual host versions remain in this
packet. Normal and optimized Python produced identical observations here.

## Limits

This is a bounded static correspondence under explicit rel32/table/slot
handling. Neither capture was run. No node115 fixture evaluation, native ABI,
all-input behavior, mutable relocation state, caller/source-type ownership,
compiler attribution, runtime equivalence, Linux build or whole-node identity
is established. The source type behind the literal kind5 remains opaque.
The original node94 evaluator, Rust implementation, fixture ledger, negative
controls, reference pins and all incomplete component gates remain unchanged.
