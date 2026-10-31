# RE-001: node94 compact-string alias feed and output-byte contract

- Component: `foundation`; one bounded RE-001 static follow-up. No gate change.
- Target: Linux x86-64 node **#94**, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Pinned reference revision: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
  No reference implementation was read or copied for this packet. The new Python
  tools and word equations are independently authored from the authenticated ELF
  and native disassembly. Imported material retains its existing rights.
- Question: what bytes and state transitions does the previously unresolved
  alias feed helper implement, and how does the producer turn them into letters?

The [earlier merged compact-string packet](../RE-001-short-string-94/README.md)
established the constructor's long-input route and ten-step producer but left
its feed helper unresolved. It could not justify an input/output alias. This
packet adds the missing feed body, its actual three-call composition, final
rounds and byte reduction, with a reproducible finite static comparison. It
does **not** complete the constructor, allocation, cache, locking or consumer
contracts. The same packet now includes the bounded, independently authored Rust
contract below, without a captured-runtime equivalence claim.

## Reproduce

Requirements: authenticated project LFS artifacts, unchanged pinned submodules,
Python 3.10+, GNU `objdump`/`readelf`, and LLVM `llvm-objdump`. No new packages,
REA, Ghidra, captured executable launch, node traffic or chain action is needed.
Both native tools are disassemblers; neither runs the input.

From the repository root:

```sh
make doctor
make verify test catalogue-check reproduce
python3 tools/short_string_alias.py --output work/short-string-alias-94
diff -ru research/work-items/RE-001-short-string-alias-94/observed work/short-string-alias-94
python3 -m unittest discover -s tests -p test_short_string_alias.py -v
make alias-rust
shasum -a 256 -c research/work-items/RE-001-short-string-alias-94/MANIFEST.sha256
```

The recorded host is macOS 15.7.7 arm64, Python 3.12.10, GNU binutils
2.47.20260726 and Apple LLVM 17.0.0. Its environment was:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/private/tmp/slop-git-lfs/bin:$PATH
export LLVM_OBJDUMP=/Library/Developer/CommandLineTools/usr/bin/llvm-objdump
```

`LLVM_OBJDUMP` can select another installed LLVM disassembler; otherwise the
tool uses `llvm-objdump` on PATH. Raw disassembly text may differ across native
tool versions. Only its local input pathname is replaced with
`<authenticated-node94>`; no instruction operands or bytes are normalized.
The input size/digest and exact FDEs are checked before analysis. GNU and LLVM
must independently agree on every instruction's start address and bytes, and
those records must cover each whole FDE contiguously and match the ELF.

`observed/records.json` retains vectors, range hashes, counts, instruction visits
and branch outcomes. `validation.txt` records actual checks and initial setup
failures. No environment/home-directory state or user fixture is captured.

## Evidence: exact bodies, call closure and state layout

Coordinates are original, unre-based ELF virtual addresses; ends are exclusive.
The FDEs are independently read with `readelf -wf`, not inferred from neighboring
unwind-index entries or source labels.

| Role | ELF VA range | File offset | Bytes | Decoded instructions |
| --- | --- | --- | ---: | ---: |
| Existing alias producer | `0x13c6060..0x13c629e` | `0x13c5060` | 574 | 151 |
| Newly inspected feed helper | `0x13daa30..0x13dac07` | `0x13d9a30` | 471 | 141 |

The producer's calls at `0x13c6100`, `0x13c611a`, and `0x13c612e` all directly
target `0x13daa30`. The feed helper has no calls or indirect jumps. The producer
also calls growth helper `0x13edc40` at `0x13c6284`; that callee remains opaque.
The evaluated producer path has synthetic output capacity 10 and initial length
0, so it never needs growth. A separate capacity-zero negative control reaches
the real growth call and refuses it, rather than substituting a fake allocator.
This is not the constructor's actual initial allocation path.

The feed helper's observed memory access layout is below. These are offsets
from its first argument, **not** an established public Rust type/ABI.

| Offset | Observed role |
| --- | --- |
| `+0x00`, `+0x08`, `+0x10`, `+0x18` | Four 64-bit state words in order `v0,v2,v1,v3` |
| `+0x20`, `+0x28` | Producer zeroes these; helper does not access them |
| `+0x30` | Total fed byte count, 64-bit wrapping addition at `0x13daa31` |
| `+0x38` | Little-endian partial word |
| `+0x40` | Number of bytes in the partial word |

The observed writes preserve an incomplete word across calls, fill it before
processing further 8-byte words, and retain the final 0–7 bytes in low bits.
The small-load paths use 4-, 2-, then 1-byte reads as available. This is why
checking only a final digest would miss a split-feed/length/tail mistake.

## Observed hash and alias equations

For every counter `i=0..9`, the producer resets its four state words. In the
equations' logical `v0,v1,v2,v3` order, the constants are:

```text
736f6d6570736575  646f72616e646f6d
6c7967656e657261  7465646279746573
```

The three feeds are **input bytes**, one byte `ff`, then **four little-endian
bytes of the counter**. Counter order/width and the delimiter are observed
instructions, not string formatting assumptions. The signed producer admission
test and counter loop are evaluated only for start 0/end 10.

All additions below wrap at 64 bits. One mixing round is:

```text
v0 += v1; v1 = rol(v1,13) xor v0; v0 = rol(v0,32)
v2 += v3; v3 = rol(v3,16) xor v2
v0 += v3; v3 = rol(v3,21) xor v0
v2 += v1; v1 = rol(v1,17) xor v2; v2 = rol(v2,32)
```

Each full little-endian word `m` is compressed by `v3 ^= m`, one round,
then `v0 ^= m`. Finalization at `0x13c6133..0x13c6221` compresses
`tail | ((total_byte_count & 255) << 56)`, xors `ff` into `v2`, performs
three more rounds and xors the four words. The independently structured word
model and the register/memory transfer model agree for the stated finite
fixtures. The constants/round structure suggest a familiar keyed-hash family,
but no library identity, compiler implementation or security property is
required or established here.

The producer then uses unsigned multiplication by `M=0x4ec4ec4ec4ec4ec5`.
The high product is copied into `r15`, whose **32-bit** low part is shifted
right by 3. The subtract/add path also has 32- and 8-bit writes; these widths
are modeled, not silently replaced with a 64-bit remainder operation.

For any unsigned 64-bit hash `h=26q+r` with `0<=r<=25`, `26M=2^67+2` gives
`hM=q*2^67+2q+rM`. The executable integer inequality
`2*floor((2^64-1)/26)+25M < 2^67` bounds the final term below `2^67`.
Therefore `floor(hM/2^67)=q` for every such `h`. The target's truncated quotient
differs from `q` only by multiples of `2^29`, which disappear from the low byte
after multiplication by 26. Its low-byte subtraction and `+0x41` consequently
give **`0x41 + (h mod 26)`**. This reduction statement has a bounded integer
proof; the hash/producer comparison remains finite static evidence.

For example, the synthetic 17-byte input `41` repeated 17 times yields
`PRZKHGDETU` under both static models. The fictional UTF-8 bytes for
`fictional-α-🌍-identifier` yield `NIRDGSWEZR`. These are transfer-evaluation
vectors, **not captured runtime outputs or claims about accepted identifiers**.

## Comparison, controls and explicit denominators

The Python transfer evaluator applies only the decoded integer, register-width,
load/store and control equations present in these bodies. It has no executable
mapping, JIT, target process, host-pointer access, syscall or external-callee
fallback. Unknown operations, memory escapes, unmodeled flags consumed by a
conditional, unclosed calls and step-budget exhaustion fail. Synthetic input
regions are read-only and exact-sized; output and stack are disposable buffers.
It is not a general x86 emulator or an independently trusted execution oracle.

The second model concatenates byte chunks, compresses full words using the
word equations above, and computes `%26` directly. It does not use target
register names, target branches, reciprocal arithmetic or partial-load paths.
Both models derive their semantics from this target, so agreement does not
rule out a shared interpretation error. Raw bytes and disassemblies are
retained for review.

- **78 distinct** synthetic byte inputs produce 78 matching ten-byte aliases
  and **780 matching full 64-bit counter hashes**, observed at `0x13c6221`
  before reduction. Comparing hashes as well as letters avoids hiding a hash
  error behind an equal remainder. Lengths include 0–64, 127–129, 255–257 and 511–513,
  plus repeated, zero, all-byte and UTF-8 fixtures. Of these, **61** satisfy
  the constructor's observed `length >16` route; shorter cases are diagnostic
  producer/helper inputs, not reachable constructor-alias claims.
- **264 feed sequences**, prefix residues 0–7 × next-write lengths 0–32,
  then the delimiter and counter, give **1,056 matching per-write states**.
  The comparison includes all four state words, byte count, partial word and
  partial length after every feed, including zero-length and exact-fill cases.
- **292/292** instructions are decoded over exactly **two validated FDEs**.
  **284/292** are visited by the positive static corpus, including all
  **141/141** feed instructions. All **12/12** helper conditional branches
  have both outcomes. One of the producer's three conditionals has both
  outcomes; its initial nonempty counter-range and preallocated-capacity
  assumptions fix the other two. The eight unvisited growth-path instructions
  are explicitly listed. These are not a whole-node function denominator.
- **Seven actual ELF instruction-byte mutations** change the delimiter,
  counter width, initial state, partial-word round, full-word round,
  finalization domain or output offset. Each is decoded again with GNU and
  LLVM **below the whole-file digest check** and then disagrees with the
  unchanged word equations. These controls do not merely reject a bad hash.
- Architectural controls cover zero-extension, partial-register writes,
  wrapping carry/overflow, unknown operations/flags, region boundaries and
  duplicate decoder records. Every outer return checks stack and nonvolatile
  register preservation. Capacity-zero reaches/refuses the opaque growth
  call. Delimiter omission and counter endian reversal change the result.

The source/tests and retained exports are hashed in `MANIFEST.sha256`.
No generated catalogue, progress record, imported evidence or submodule changed.

## Bounded Rust implementation and build comparison

The library lives under `src/` as required by `src/README.md`. The relocation
preserves the Cargo manifest, lockfile, Rust library/tests and contract-vector
bytes. Retained Rust results were regenerated from the new path; the prior
packet remains in Git at `995414a1a99498918d89d9cebe1cd045ad4c6a93`.

The same PR adds [`src/node94-alias`](../../../src/node94-alias/README.md).
This is a real standalone library with its own `Cargo.toml` and `Cargo.lock`, no
registry dependencies or build script. It does not create a root workspace or
pretend that the inferred source tree builds. `AliasFeed::write` preserves the
partial little-endian word across arbitrary chunks. `finish` implements the
observed length-byte/final-round contract without consuming the state.
`alias10` returns a fixed ten-byte array. It copies the state after input for
each counter; the target re-feeds input. Output and complete counter hashes are
compared, rather than assuming that reuse is equivalent.

`tools/short_string_alias_rust.py` authenticates the complete node #94 artifact,
dual-decodes the two whole FDEs, and regenerates every committed Rust expectation
directly with `alias_transfers` and `feed_transfers`. It does not use the second
word model or Rust to make its expectations. The 78 alias/full-hash rows must
also equal the unchanged original observations. Streaming rows retain all four
states per sequence, including empty writes. A changed fixture stops the check.

The Rust tests compare **78 aliases, 780 full counter hashes, and 1,056 states
over 264 split-feed sequences per profile**, in both debug and release. Eight
valid, compiling Rust-source changes must make the same comparisons fail:
initial word, delimiter, counter byte order, mixing rotation, word byte order,
length byte, finalization domain and output offset. Original seven actual ELF
byte controls and the growth-call refusal remain in the unchanged Python tests.
No captured instruction is copied into executable memory or linked into Rust.

The comparison command uses `cargo test/build --locked --offline` with the
recorded existing toolchain. It creates two new target directories on each run.
Their release `.rlib` files must be raw byte-equal; no bytes are normalized. This
is a repeated build of this host library, not an x86-64 target build or a
comparison with captured node machine code. The release profile explicitly
enables overflow checks; every observed wrap uses `wrapping_add`.
`rust/comparison.json` records source/fixture hashes, tool versions, commands,
denominators, corruption outcomes and the two artifact hashes.
`rust-validation.txt` records the actual checks and the initial format correction.
Paths in Cargo logs alone are replaced with placeholders; test results are not.

## Results and remaining questions

The previous missing feed body is now tied to exact FDE/bytes, calls, state
offsets, streaming updates and producer finalization. Static vectors distinguish
delimiter/counter/byte-order mistakes and the target's actual output-byte
arithmetic. Applicable checks and before/after counts are in `validation.txt`.

**No gate is requested.** A bounded host Rust implementation, builds, repeated
library-build identity and finite static comparison are measured. The whole
foundation component is not built or recovered. Captured native runtime
comparison, x86-64 target-build identity, whole-ELF identity and hosted CI remain
unmeasured. The observed memory offsets are not exposed as a Rust or FFI ABI.
No #115 or visor result transfers from this target. No allocation, panic,
unwind, cache-table equality/hash, lock, accepted-input, serialization or
consumer contract is closed by these finite preallocated-path evaluations.
The next concrete question before a drop-in compact-string implementation is
the constructor's cache-miss allocation and table-helper ownership contract.
