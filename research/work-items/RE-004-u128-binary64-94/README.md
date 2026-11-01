# RE-004: unsigned128 to binary64 returned bits

Task/component: RE-004 arithmetic, foundation runtime dependency. Bounded
question: what returned binary64 bits does node94's complete132-byte leaf at
ELF VA `0x565ff80..0x5660004` produce for every unsigned128 input?

Target: Linux x86-64 node94,91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base:`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. All addresses are ELF
virtual addresses before load bias. All full-component gates remain false.

The independently derived native theorem covers all2^128 words, including
zero despite architecturally undefined BSR destinations. Entry RDI is the low
word and RSI the high word; the projected output is XMM0's low64 bits. The
integer-only leaf implements round-to-nearest, ties-to-even independently of
MXCSR rounding/FTZ/DAZ settings. Its only XMM instruction copies the final bits.
It has no calls, explicit memory operands or static-data reads; an ordinary
valid return word is a premise. Original ABI/types, physical clobbers, caller
meaning and broader processor-fault behavior are outside this value theorem.

Current-main/live-PR intake found no unsigned132 reconstruction or byte window.
The signed168-byte conversion in openPR1411 owns `0x565f4f0..0x565f598`.
PRs1383/1377 concern disjoint64-bit quantity paths at `0x3c06160` and
`0x4cda1a0`. Their implementations were not used. Existing packet mentions of
this unsigned leaf as an adjacent FDE boundary do not establish its semantics.

## Observed native and official artifact evidence

`native/record.json` admits the immutable complete target and official archive
by full SHA-256. It binds the132-byte executable section/PT_LOAD mapping,
actual complete FDE/CIE,36 raw native instruction rows and sole RET. It checks
every RELA table for code overlap and globally unique selected-slot writes.
GOT slot`0x5775060` has exactly one symbol-zero RELATIVE record to the leaf;
no relocation overlaps the body. The complete GNU listing and full numerical
derivation are retained in `native/` and `PROOF.md`.

Both defined official `__floatuntidf` candidates match all132 target bytes
without masks. Each is a complete symbol-at-zero132-byte allocated executable
PROGBITS section with no code relocations. The official4,400,606-byte rlib has
SHA-256`f49a2fe8dd80c6b314f9f2c7b4f1f2837f829dea93aed8c78f67ae87ef55a8f6`.
This named published-artifact correspondence is separate from our Rust's
numerical qualification and does not identify the original compiler/source build.
Alternative definitions supply one selected target interval, never two.

The actual collector and ten focused native/control methods passed. They cover
the complete body, an arithmetic opcode mutation bypassing full-file admission,
truncation, actual FDE-range mutation, wrong relocation kind, duplicate/partial
slot writes, changed target, unpinned archive and both complete source definitions.
The first invocation failed to create output because the new view lacked its
ignored `work/` parent; its exact diagnostic/streams remain under
`observed/initial-output-parent-failure/`. Creating that parent allowed the
unchanged collector and all ten controls to pass; no native guard was relaxed.

## Independent pre-source authority and implementation

An independent root worker froze16,614 rows covering16,610 distinct u128 values
before new Rust. `preparation/root-FREEZE.json` has SHA-256
`46fcb655e66a84595ac8786ab5c7a4ba67b4912ca7ce0a2329f51f34719b9230`.
Its original generator, stimulus and expectation bytes are preserved unchanged
inside deterministic gzip files, with their original uncompressed hashes.
The independent integer RNE oracle was corroborated against CPython conversion
for every row. The later independent complete native proof also preceded Rust
and is retained with its explicit proof/authority linkage receipt.

Coverage includes zero/every binade, exact53-bit inputs, both midpoint parities,
every sticky position across75 discard counts, carry into the next binade,
maximum u128 and reordered duplicates with new opaque IDs. A twenty-case
unchanged subset was separately frozen before `lib.rs` for one ordinary unit
method. These finite vectors support the separate all-input proofs.

The independent `no_std` Rust library determines the binade by integer shifts,
splits the retained prefix and exact residue, applies the midpoint/parity rule,
and assembles the encoding. `SOURCE-PROOF.md` proves every shift, narrowing
conversion and arithmetic bound for the complete domain. No integer-to-float
cast, division/remainder, unsafe code or inferred private implementation is used.
The input-only client receives one stimulus file with `id|n32hex` and writes
`id|bits16hex`. Expected answers are compared outside its process. This is an
input data-flow restriction, not a filesystem sandbox.

`tools/u128_binary64_reference.py` authenticates the original freeze, independently
rechecks every expectation through ordered IEEE encoding search and exact
rational distances, and revalidates the actual target body/FDE/slot. It is pure
mathematics and static parsing, with no opcode/PC/register interpreter.
The task-specific qualifier adapts the reviewed local remainder build recorder
because its fixed interface and division guard cannot qualify this conversion.
It adds the required conversion-delegation guard; existing tools stay unchanged.

## Rights and reproduction

`SOURCE-PROVENANCE.json` binds the official dist, source revision and complete
upstream multi-license. The full15,078-byte license was freshly read from its
fixed official revision and matched the retained bytes and Git blob. Imported
official-artifact excerpts retain those terms; new implementation/proofs/tooling
are MIT. No can1357 implementation was copied. The named official source identity
was checked after the author's native theorem; introductory source comments were
displayed, and no official implementation was copied into the new Rust.

The exact research Rust1.94.1 provider was restored from authenticated official
archives into an owned prefix. Its103 component-manifest payloads and two
installed manifests are audited, with complete distribution licenses preserved.
It is a research provider, not an identified original node compiler.

From the repository root, with an existing empty output parent:

```sh
python3 -B tools/u128_binary64_contract.py \
  --builtins /path/to/libcompiler_builtins-58c8d4715a55733a.rlib \
  --output /tmp/new-u128-binary64-native
python3 -B -m unittest tests.test_u128_binary64_contract -v
python3 -B tools/u128_binary64_rust.py \
  --rustc /tmp/hl-resume-20261101/toolchain/prefix/bin/rustc \
  --provider-audit /tmp/hl-resume-20261101/toolchain/PROVIDER-AUDIT.json \
  --output /tmp/new-own-u128-binary64 --controls
```

The build recipe uses edition2021, overflow checks, one codegen unit and O0/O3,
with explicit GNU bfd selection. It checks actual library rlib/object/IR for
floating conversion/arithmetic and numerical runtime delegation. A separately
labelled own cast wrapper must be refused before client link/execution. Three
normal-returning compiled semantic mutants and comparator corruption controls
must demonstrate observable disagreements. One additional O3 build checks raw
own-build reproducibility, which is separate from the official132-byte match.

Native collection is observed; actual Rust qualification and final repository
checks are pending at this source checkpoint. No green result is inferred.
The expanded repository suite, hosted CI, captured code/instruction evaluator
execution, full-node/whole-ELF equivalence and all full-component gates remain
NOT RUN or unclaimed. Next question: which real callers supply the unsigned
word pair and what units/policies do they impose beyond this closed leaf?
