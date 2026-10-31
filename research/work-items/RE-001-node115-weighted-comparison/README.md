# RE-001: node #115 checked folds and strict wide comparison

- Component: foundation / quorum-policy-associated arithmetic; preparatory mapping for RE-008, not completion of it.
- Target: node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Bounded question: which checked sums feed the source-associated comparison, and is the final predicate a wrapped-word or wide strict comparison?
- Observation: on normal completion of the second fold and raw first-fold return word 1, AL is 1 exactly when `2*S < 3*B`, evaluated as unsigned 128-bit products. Checked-add overflow rejects the normal true route.
- No complete consensus policy, validator/selected/total set interpretation, vulnerability, Rust implementation or component gate is claimed.

## Scope and coordinates

All ranges are original ELF virtual addresses, half-open, validated against actual FDEs and independent GNU readelf output. Raw FDE/CIE bytes and file offsets are retained in records.json.

| Role | FDE range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| source-associated context | `0x3bcad50..0x3bcae80` | 304 | 78 |
| second fold / final comparison | `0x422e280..0x422e403` | 387 | 107 |
| first checked fold | `0x43516d0..0x4351882` | 434 | 111 |
| second-stream next adapter | `0x37c4430..0x37c4644` | 532 | 126 |

The measured denominator is **four full FDE bodies, 1,657 bytes / 422 native instructions**. Every body starts at its actual entry and complete byte coverage is checked. No normalization mask, source build or Rust binary comparison exists here.

The context loads Location `0x6475bd8` at `0x3bcae64` and calls the comparison at `0x3bcae73`. The relocation, path length and line/column bind this to `base/src/quorum_policy.rs:72:9`, not a recovered original function name. The first lookup's imported comparator slot `0x64dfb50` is actual GLOB_DAT symbol 12, `memcmp@GLIBC_2.2.5`; this is a binding observation, not closure of lookup semantics.

## Folds and status

The first helper returns a raw status word in RAX and a checked u64 sum in RDX on its normal status-1 route. The comparison retains these in R14 and RBX. Its measured code uses 20-byte keys and two map-shaped lookup routes. Key iterator `0x37c5980` and lookup `0x4553fd0` remain unmeasured; collection identity, key membership, duplicate behavior and concrete map/iterator ABI are unknown. **B** names only that normal returned sum.

The second fold initializes R12 to zero and adds qword weights. Its fast path uses 32-byte rows and weight offset `+0x18`; its other path calls measured next adapter `0x37c4430` and consumes a returned weight pointer. **S** names this checked sum, conditional on valid input memory and normal helper/iteration completion. No claim is made that these two inputs represent total versus selected validator weight.

The actual ADD/unsigned-carry transfers are:

- `0x4351714`, JB at `0x435171c` to `0x435186e`: first fold returns raw status 0 on sum overflow.
- `0x422e2f0`, JB at `0x422e2f7` to `0x422e3f3`: fast second-fold overflow returns AL 0.
- `0x422e3b1`, JB at `0x422e3b4` to `0x422e3f3`: other second-fold overflow returns AL 0.

The final check at `0x422e3cd` requires retained first status exactly 1. It occurs **after** second-stream processing; invalid first status is not claimed to skip that processing or its effects. Allocation, invalid pointers, nontermination, exceptional exits and opaque lookup behavior are outside the local normal-return theorem.

## Strict wide predicate

Let `M=2^64`, with `0<=S,B<M`. The final instruction sequence is:

```
0x422e3d6  SHR RCX,63       # RCX was S
0x422e3da  ADD R12,R12     # low limb of 2*S
0x422e3dd  MOV EDX,3
0x422e3e2  MOV RAX,RBX     # B
0x422e3e5  MUL RDX         # both limbs of 3*B
0x422e3e8  CMP R12,RAX
0x422e3eb  SBB RCX,RDX
0x422e3ee  SETB AL
```

For every u64 S, `2*S = (S>>63)*M + ((2*S) mod M)`. MUL supplies the exact low and high limbs of `3*B`; both products fit within 66 bits. Let the low comparison borrow be `c = left_low < right_low`. SBB computes high-left minus high-right minus c. Its final carry is true exactly when `left_high < right_high+c`, which is equivalent to unsigned 128-bit less-than. High limbs are bounded (left <=1, right <=2); the added borrow cannot overflow. Equality has no borrow, so ties return false, including S=3,B=2 and both zero. Values such as S=B=UINT64_MAX require the high limb and return true.

This is an all-domain algebraic proof for the extracted sequence, not target execution or a source implementation. The tests compare the two-limb relation against unbounded integer arithmetic across carry boundaries and strict-tie neighbors; they do not use a virtual CPU.

Three **actual operand** counterfactuals change the extracted relation before rejection:

- Factor immediate 3 -> 2 at `0x422e3de`: S=B=1 changes true to false.
- Carry shift 63 -> 62 at `0x422e3d9`: S=B=2^62 changes true to false.
- SETB opcode 0x92 -> SETAE 0x93 at `0x422e3ef`: S=3,B=2 changes false to true. This flips the carry predicate; it is not a claim about SETBE implementing a full wide less-or-equal operation.

Additional controls alter actual sum carry branches, row stride/offsets, status, direct call displacements, source metadata/LEA, relocation addends, code bytes and FDE extents. Public generation rejects modified, truncated and wrong-release input before output or native analysis.

## Reproduce and limits

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. From the repository root with materialized inputs and native GNU tools on PATH:

```sh
python3 -B tools/weighted_comparison_static.py --output work/weighted-comparison-check
# Compare generated files with this packet except README/manifest.
python3 -B -m unittest discover -s tests -p test_weighted_comparison_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-001-node115-weighted-comparison && shasum -a 256 -c MANIFEST.sha256)
```

The producer authenticates the complete capture before parsing, output or native calls. Readelf/objdump receive a private byte-identical snapshot. Exports are full, unnormalized UTF-8/LF text. Retained records include the observed source and call/relocation bindings, complete body hashes and original unwind records.

Before: main has no packet binding this source context, checked-fold failure routes and wide comparison. After: the four actual bodies and the conditional arithmetic theorem can be independently regenerated and attacked with real operand corruption controls. No captured binary/emulator, validator state, network, wallet, signing or chain action is used. Imported source/code/pins are untouched. All component gates stay false. Complete callers, collection semantics, unmeasured helpers, Rust ABI, unwind behavior, runtime equivalence, protocol correctness and hosted CI remain unproved. New tooling/docs are independently authored under root MIT; no inferred unlicensed source was copied.

Next question: close the two first-fold iterator/lookup helpers and caller collection provenance before assigning policy roles to S and B or proposing any implementation.

Observed local results: six focused tests passed in **16.053s**. Required
`make doctor verify test catalogue-check` passed **437 tests in 168.007s**, and
`make reproduce` passed. Packet hashes and staged whitespace were
also checked before submission. These are local checks, not hosted CI.
