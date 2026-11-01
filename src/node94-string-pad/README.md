# Node #94 Unicode precision and string padding requests

This independently authored safe Rust closes the normal callback/header-cell
relation of the complete `Formatter::pad` body at ELF VA
`0x1573450..0x1573889`: 1,081 bytes / 300 instruction rows, SHA256
`f958a0383269ead1a2056ba42785c9050e46a57aa0f990a27976fe27cb5eee77`.
Target node #94 SHA256:
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The original adjacency seed was a different function and supplies no label here.

This advances the RE-005 formatting dependency question: Unicode scalar
precision, option-bit gating, width, default-left alignment and raw versus
canonical callback errors. The fixed 1,483-byte character-counter relation is
credited to reviewed PR #1439 and freshly bound here; it earns no duplicate
recovery claim. Main/data/helper bindings and the independent mathematical proof
are in `research/work-items/RE-005-string-pad-94/`.

## Chosen interface and domain

`pad_str` takes a valid immutable UTF8 string, one borrowed writer state,
`Context` cells, stable unique logical `Table` IDs and a normal callback.
`tailword` encodes flags32,width16,precision16 as chosen values, rather than
asserting a native Rust layout. Logical data/table/method tokens are labels;
native pointers and private ABI identity are not recovered.

- If both option bits27/28 are clear, the helper requests the entire string
  exactly once and forwards the callback's raw `u8`, ignoring raw width/precision.
- Otherwise bit28 selects the first `min(precision, scalar_count)` Unicode
  scalars at a complete UTF8 boundary; without it the whole string is selected.
  The counter implementation is real scalar classification of UTF8 bytes.
- After selection, raw width16 applies even with bit27 clear. If no padding is
  needed, one Str(selected bytes) request forwards raw status, including empty
  selected strings and nonzero statuses other than1.
- Padding uses raw fill21 and preceding counts `[0,A,floor(A/2),0]` for alignment
  codes0..3. Default code3 is left. It requests preceding fills, one selected
  string, then trailing fills; every padded error returns1 and success returns0.
- Data/table IDs remain cached, while method cells reload on every request.
  Header/data/table/method mutations made by callbacks persist. The helper
  performs no header write or automatic zero-padding restoration.

The domain is x86-64/usize64, readable nonwrapping strings of at most isize::MAX
bytes, valid stable unique logical tables, and callbacks returning normally.
Input/code/active-frame storage is immutable and separated from invalid aliases;
only sequential supplied cell changes are included. Char requests carry raw
`u32`, including values outside Unicode scalar range. Rendering, native ABI and
pointer identity, hidden registers, faults/unwind, concurrency and whole-node
behavior remain outside this relation. No component gate is requested.

## Build and verification scope

The library is `no_std` and forbids unsafe code. It uses the real admitted
official Rust1.94.1 research provider; there is no invented Cargo workspace or
dependency graph, native-byte transplant or fixed helper stub. The input-only
client accepts eight raw fields and never reads expected output or layout plans.

Before this source was authored, the independent native-derived proof and corpus
were sealed: 26,054 unique inputs, 9,915,008 callback observations and 49,649
exact adjacent-event RLE records, maximum65,536 callbacks per measured case.
Freeze SHA256:
`00eaff92d84ae4a569aab8c1950fa991f8c271dd4445b3a02fb4f11b697d06e9`.
RLE is a lossless observation encoding; the Rust performs individual callbacks.

This source checkpoint is uncompiled. Actual O0/O3 results, raw artifacts,
controls, before/after source/target/pin/provider/linker audits and peer review
must be retained before any implementation result is posted. Full `make test`,
expanded instruction evaluators, captured-program execution, hosted CI and
full-node builds are NOT_RUN. Existing component gates remain false.

New code/docs are project-authored MIT work. Captured and official libcore byte
evidence retain original rights and full upstream notices. The unlicensed
can1357 implementation was not copied. The research provider is not a claim of
the target's original compiler identity.
