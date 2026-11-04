# RE-004: reconstruct node115 spot metadata decimal conversion

Component assets; established quantity/granularity semantics under approvedScope.
Sole target Linux x86-64 node115 SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105896032 bytes.
Independent base05bc2de303c05525b71e7e257426e741bc66a390. Unrebased ELF VAs.
New MIT Rust and analysis are independently authored. No unlicensed inferred
implementation is read/copied. Merged #2289 is credited static evidence, not
a new discovery claim. Its actual source Locations bind l1/src/spot_meta.rs
590:25 and119:33 at the two retained diagnostic entries.

## Native scope and raw memory contract

Full FDE0x29aea00..0x29aeaf2 is242 bytes/73 instructions. Actual FDE/CIE and
agreeing full GNU/Capstone exports are retained. All ordinary207 bytes/66
instructions are interpreted and all66 instruction starts visited. Stop before
0x29aeadc (first index A) or0x29aeacf (second index B). The remaining7 diagnostic
instructions, opaque callees and unwind behavior are not implemented. Ordinary
paths execute their actual RET; require RAX equal the supplied output pointer
and RSP restoration. No supplied helper result, callback or target stub exists.

Inputs are RDI=initialized16-byte output, RSI=raw unsigned amount, RDX=first
index, RCX=descriptor, RSP=synthetic stack with return marker. Descriptor fields
+8/+0x10 hold first pointer/length, +0x20/+0x28 second pointer/length. First rows
have32-byte spacing and contain the second index at+0; second rows have344-byte
spacing and decimal byte+0x48. Synthetic disjoint valid storage, lengths0..4
and0..3, arbitrary row padding, all256 decimal byte values, high-bit indices,
amount boundaries and varied output canaries are included. Fixture bounds are
not claims that these table lengths or arbitrary states are production-reachable.
Unspecified registers/flags remain unknown, including the pushed entry RAX.

First index >=first length stops at A without reading its row. Otherwise the
loaded second index >=second length stops at B before its row is read. A/B are
raw PCs before opaque diagnostics, not recovered errors or native return tags.
All ordinary input bytes must remain unchanged. Memory access is restricted
to declared descriptors/arrays/output/stack; input writes, calls and CFG escapes
fail closed. The logical Rust slices model selected row values, not these native
strides, Rust layouts or ownership. Aliasing, invalid native objects, allocation,
producer invariants and original type identities remain outside the contract.

## Established conversion and complete output observation

For decimal>8, write WORD0x6a only. For decimal0..8, construct10^(8-decimal)
through the original conditional multiplications. Amount/divisor uses32-bit DIV
only when both fit u32; otherwise64-bit DIV. Nonzero remainder writes WORD0x6a
without writing the payload. Zero remainder writes the quotient at output+8
and WORD0x1a2. Both paths return the original output pointer.

The oracle retains ALL16 output bytes, not only an invented Option quotient.
Thus bytes2..7 and rejected/inactive bytes8..15 remain their caller-supplied
values. No output padding is replaced with zero or assigned meaning. The Rust
library operates on an initialized byte array and makes exactly the observed
writes. Caller canaries and every input byte are checked, with no normalization
mask. The output16-byte window is measured, not a claim about complete native
result allocation size. Domain asset names, units, schema and runtime use remain
unproved.

## Original-first evidence

Commit045c9a21c7362a2100ce0e942d94514fbaacd3e7 sealed original observations
before new Rust existed.4048 distinct fixtures produce388A,105B and3555 actual
ordinary return observations:230 accepted0x1a2 and3325 rejected0x6a. Complete
input/output hashes are in FREEZE.json.73 frozen representative rows cover each
valid decimal, exact/inexact boundaries, guards, varied canaries and controls.
Stimulus powers/division boundaries choose inputs only; expected results come
exclusively from actual original instructions. Fifteen actual byte-COW controls
alter both bounds, row strides, decimal offset/limit, power multipliers, remainder
branches, output tags or quotient destination and produce changed observations.
The captured artifact is SHA-authenticated before/after and never modified.

The unchanged MIT project instruction CPU and ELF View from
RE-014-price-core-115 are attributed reuse. Parent #2289 records, frames,
relocations and disassembly are hash-pinned context. Quantity preparation at
0x41c57f0 and Decimal96 normalization at0x3be4ba0 are different owners/contracts.
All-state PR, open-issue, spot/divisibility, metadata/Rust and exact-address
searches found no competing Rust implementation within indexing/unpublished
work limits. No claim/issue/comment was created.

## Reproduction and limits

From repository root, source ../hl-env.sh; serial0.10 active-wall duty,
Python3.12.14, Capstone5.0.6, GNUobjdump2.47.20260726, macOSarm64:

    python3 research/work-items/RE-004-spot-decimal-115/native.py
    python3 research/work-items/RE-004-spot-decimal-115/build.py --rustc <rustc1.94.1> --output <new-directory>
    python3 -m unittest discover -s tests -p test_node115_spot_decimal.py -v

Historical freeze command is in FREEZE-NOTE.md; run it only at the pre-Rust seal
checkout. Current native.py/build.py regenerate and check frozen stream hashes.
The input-only adapter receives no expected data. New no_std Rust has no external
dependencies or invented original Cargo graph. Research compiler provenance is
rustc1.94.1/LLVM21.1.8, edition2021, hostaarch64-apple-darwin; not an original
Linux build recipe or byte-match claim. Build/check reports state only actually
observed results. No captured executable/Unicorn, service, chain, signing,
wallet or network-facing runtime runs. All92 gates stay false.

Next: recover caller-owned metadata producers and domain invariants before
connecting this raw conversion to a production asset interface. Neither this
leaf nor green tooling tests establish complete assets/component equivalence.

## Observed independent Rust comparison

Original expectations were sealed at045c9a21 before Rust source existed.
Both opt0/3 input-only clients match all4048 original observations exactly;
optimized own-library repeat is identical. Both ordinary tests pass at each
unmodified profile. Eleven compiled corruptions yield3611,3541,62,181,339,230,
3325,189,180,230,3555 mismatches and every mutant fails its ordinary tests with
exit101. Complete build/control run170.247s PASS. rust-results.json retains
exact compiler/stream/source hashes and all observed variant outcomes.

This agrees with the defined raw observation scope; it is not arbitrary-memory,
error-handler, native Rust ABI, compiled-body or full-assets equivalence.

## Scoped repository checks

Six focused tests, formatting, Clippy, twelve packet-integrity tests, doctor,
artifact/import/packet verification, catalogue generation/check and actual
inventory reproduction pass. Complete scoped run367.520s; commands/timings are
in repository-checks.json. Only catalogue steps use the exact previously
submitted #2655 immutable-snapshot helper to avoid the measured39.47GB repeated-
read blocker. validation-overlay.json pins both versions. The baseline helper
is restored byte-for-byte before reproduce/commit, and is absent from this diff.
Those two steps are not unmodified-head catalogue validation.

Earlier full585/584-file upstream passes belong to #2655/#2692. This PR's own
full CI is pending; no local full-suite or hosted-CI pass is substituted.
