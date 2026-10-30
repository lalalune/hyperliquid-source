# RE-001: node94 filtered uniqueness helper and compact diagnostic

- Component: foundation iterator helpers; RE-001 function ranges and cross-references.
- Target: node #94, Linux x86-64 ELF, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base/source and reference pins: `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  imported reference commits remain those in that revision. `base/iter.rs` is
  an unlicensed inferred lead, not authoritative source or copied implementation.
- Observations: two actual FDEs, one specialized helper, one selected caller,
  source Location and relocation bindings. Tree and return names below are
  interpretations of fields/control flow; concrete Rust types remain unknown.
- No reconstruction/progress gate requested. No captured executable run.

## Question and correction

Which bytes and caller establish the reference's `unique_elem` label, what is
compared for uniqueness, and is the leading dot in the inferred panic message
actually punctuation? The reference alone cannot answer these questions. It
spells `.ChamIterator::unique_elem...`; the target starts a compact formatting
descriptor with `0x2e`, followed by **46 bytes** of literal text beginning
`ChamIterator`. Treating the whole descriptor as an ordinary string includes
the length tag as a dot and omits the placeholder structure.

The relevant format layout is documented by the compiler-stamped Rust revision:
[core fmt contract](https://github.com/rust-lang/rust/blob/e408947bfd200af42db322daf0fadfe7e26d3bd1/library/core/src/fmt/mod.rs#L612).
A separately fetched copy of that file hashed
`ff56f0d7f3ce245b6171f2b742bfa07e1a7596158e43a9917a0340c7e9eb8a27`.
The scoped decoder supports only the short literal lengths, default placeholder
`c0` and final `00` forms actually present here. It yields literal segments
`ChamIterator::unique_elem: not unique elems: [`, `, ` and `, ...]`, separated
by two placeholders. This is a descriptor interpretation backed by the stamped
format contract, not execution/proof of the complete target formatter or its
callback at `0x33de3e0`. Placeholder values and rendering remain unproved.

## Reproduce

From the repository root with pinned LFS captures materialized and GNU binutils
on PATH (macOS host; Python 3.12.14, GNU readelf/objdump 2.47.20260726):

```sh
python3 -B tools/unique_value_static.py --output work/unique-value-94
python3 -B tests/test_unique_value_static.py
make doctor verify test catalogue-check
make reproduce
```

Compare the four generated files with the adjacent saved packet. The generator
reads and authenticates one snapshot before analysis and writes that snapshot
to a private temporary file for both native tools. It invokes `readelf -wf` and
`objdump -d -M intel --insn-width=16 --start-address=... --stop-address=...`.
No captured binary is spawned. Raw objdump temporary paths are replaced by
`<authenticated-node94>`; no instruction/data normalization mask is applied.

`frames.txt` gives actual ranges `0x33690c0..0x33694fc` (1,084 bytes) and
`0x336a4e0..0x336a890` (944 bytes). `records.json` includes the full body bytes,
file offsets, SHA-256s, checked instruction bytes, RIP targets, relocated slots,
source Location and compact descriptor. GNU decoded starts confirm each checked
instruction boundary. An independent, transient Capstone 5.0.6 sweep consumed all
1,084/944 bytes in 239/195 instructions respectively; this is an additional
boundary check, not independent source reconstruction.

## Evidence

The helper searches the outer structure rooted at object `+0x30` using RCX,
loading height at `+0x38`, node count at `+0x21a`, keys at `+0x10` and children
at `+0x220`. Missing outer entry returns raw tag `0x97`. Empty selected root
or count produces `0x2a`. These are B-tree-like layout observations, not a
recovered generic type or assertion that every possible state is valid.

At `0x3369367`, the selected index is scaled by 64. The filter compares 16 bytes
at record `+0x18` with RDX input, then four at `+0x28` with input `+0x10`.
SSE byte-equality masks are ANDed and compared with `0xffff`. The upper 12
lanes of the second comparison are zero-vs-zero, so **all 20 input bytes**
must compare equal. The payload address at `0x33693a3` instead scales by 32
and adds `0x2c0`. The 20-byte filter and 32-byte compared value must not be
conflated.

The r8b flag initially has no saved value. A first matching value is saved;
subsequent matching values compare **all 32 payload bytes** through two SSE
comparisons at `0x33693fc..0x336942c`. A mismatch branches to `0x33694b2`;
an equal value is accepted, copied and traversal continues. Exhaustion with a
saved value writes its two halves to output `+2` and `+0x12` and tag `0x186`;
otherwise the output is tag `0x2a`. Several equal selected payloads therefore
satisfy this specialization; it is not a count-of-selected-elements-equals-one
check. Iterator advancement and inner node fields (`+0x428`, `+0x42a`,
`+0x430`, `+0x438`) are retained in full raw disassembly rather than replaced
with an invented container implementation.

The selected caller sets RDI to output stack storage, RSI to r8 (object),
RDX to rcx (filter), and RCX to `[r8+0x48]` at `0x336a51c`. Its call at
`0x336a528` uses GOT slot `0x5773148`, whose RELATIVE addend is `0x33690c0`.
It consumes the output word and two 16-byte halves, testing tag `0x186` at
`0x336a54c`. This is one verified incoming edge, not an exhaustive xref census.
It does not claim the distinct validator-profile function covered by PR #98.

The unequal-payload path uses descriptor VA `0x1ed4ee`, callback `0x33de3e0`,
Location slot `0x56e9e38` -> path VA `0x1ebfb7`, length 45, line 132 column 21,
`/home/ubuntu/hl/code_Mainnet/base/src/iter.rs`. Call slot `0x576e098` resolves
to `0x157b810`. Another branch references Location slot `0x56e9fe8` and call
slot `0x576e470` -> `0x157a9f0`; the former points into a standard-library
btree navigation source path. These call targets are bound, not analyzed to
transitive closure or certified as a specific exported Rust panic API.

## Validation and limits

Five focused tests pass: real specialization/tag bindings; exhaustive **2^20**
boolean byte-equality patterns for the observed filter mask reduction; scoped
format interpretation and four malformed descriptors; **15** one-byte changes
to actual instruction/data/source bytes below the digest admission gate; and
native regeneration of all four saved files. The boolean proof models the
observed mask expression, not target execution or whole-function equivalence.
The corruption controls establish rejection of changed relevant evidence,
not a general malformed-ELF or arbitrary-instruction verifier.

Required checks: doctor ready; verify validates pinned artifacts/imports and
signatures; **436 tests pass**; catalogue check passes. `make reproduce` must
also pass before submission. SHA256SUMS binds the durable packet and new code.

No independent Rust implementation, build recipe, Cargo workspace, binary
comparison or runtime equivalence has been produced. Ownership, concrete
address/key/value types, valid-state invariants, complete outer/inner traversal
proof, other monomorphizations, helper semantics and complete formatting remain
open. All component gates stay false. The next useful question is whether the
selected caller's surrounding traversal maintains the container invariants
needed for every observed child/entry access; this packet does not answer it.
