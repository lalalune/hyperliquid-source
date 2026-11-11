# RE-001: node #115 scalar reader and reduction contract

- Component: foundation; bounded arithmetic dependency used by signer backends.
- Target: Linux x86-64 node **#115**, 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/base: `0781ce04826eeefd89fe336cb8ea073be0c1de30`.
- Question: what do the two 32-byte readers called before the established
  two-field storage paths return, including the optional overflow destination?
- Intended files: this packet, `src/node115-scalar-reduction/`, and regenerated
  inventory banners only. No imported evidence, pin or progress gate changes.
- Status: observed instruction/layout facts and conditional static proof;
  original source identity and complete callers remain unresolved.

## Gap addressed and measured scope

The merged [two-field storage packet](../RE-001-node115-secp-storage/README.md)
left the producer chain unresolved. This contribution closes one concrete leaf
on that chain: both scalar readers' entire arithmetic/output relation. The
result also supplies the meaning of the overflow dwords combined by the nearby
compact-record parsers. It does not close their surrounding cryptographic core.

| Body | ELF VA, end exclusive | File offset | Bytes | Instructions |
| --- | --- | --- | ---: | ---: |
| A | `0x6321680..0x632179d` | `0x6320680` | 285 | 83 |
| B | `0x6330f50..0x633106d` | `0x632ff50` | 285 | 83 |

Denominator: **two complete bodies, 570 bytes / 166 instructions**. Their bytes
are identical, SHA-256
`5bfa12c91507b12120e2bab824f10448a08e0ec6b88ad40d60c4e4e10f6da9d2`.
Each has one matching FDE, executable section and PT_LOAD mapping, a terminal
RET and three INT3 bytes before the next FDE. Complete linear decoding and
control-flow validation supplement the FDEs; an unwind entry alone is not a
function-boundary proof. No calls, RIP-relative data or code relocations occur
inside either body. Constants are instruction immediates. Raw CIE/FDE records
and full instructions are retained in [observed/records.json](observed/records.json).
GNU/Capstone agree on all 166 instruction starts, bytes and mnemonics; GNU
readelf independently confirms both ranges. Operand-semantics agreement is not
claimed by that decoder check. Code normalization masks: **none**.

## Established contract

Assuming valid disjoint input/output/optional-flag/stack storage and the usual
System V register setup, RSI points to 32 input bytes, RDI to 32 output bytes,
and incoming RDX is null or points to one writable dword. Let `x` be the
**big-endian** integer represented by the input and let

```text
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
```

Then both helpers write exactly four little-endian qwords representing
`x % n`, least-significant limb first. If RDX was nonnull they also write
**dword** `1` iff `x >= n`, else dword `0`; a null flag pointer is not written.
The input is not written. All six callee-saved GPRs and stack balance are
checked. The model's data footprints and PUSH/POP slots are recorded separately.
Return-register value is not part of the Rust API or theorem.

The helper reduces values at/above `n`; it does not itself reject them. Zero
remains zero with flag zero. At `n`, output is zero with flag one. At `n-1`,
output is unchanged with flag zero. At `2^256-1`, output is `2^256-1-n` with flag
one. Since `2*n > 2^256-1`, one conditional subtraction suffices for every input.

The target's comparison uses the low threshold `0xbfd25e8cd0364140`, the middle
thresholds `0xbaaedce6af48a03a/3b` and the top-limb boundaries. Its reduction adds
the complement constants `0x402da1732fc9bebf`, `0x4551231950b75fc4`, and the
selector with ADC propagation. The static transfer functions preserve those
operations, rather than replacing them with a trusted modular-arithmetic helper.

Seven solver checks are **UNSAT**: output disagreement for both complete copies
under both flag-pointer cases (four), flag disagreement for both copies (two),
and output at/above `n` (one). These cover all 256-bit inputs under the explicit
[model](MODEL.md), not execution of the captured instructions. A separate
arbitrary-precision remainder oracle agrees on **281 cases**: all 256 single-bit
inputs, zero, a 17-value neighborhood of `n`, cross-limb boundaries and the
maximum input. The full rows are frozen in [observed/boundaries.tsv](observed/boundaries.tsv).

The numerical order agrees with the public MIT-licensed
[secp256k1 order constants](https://github.com/bitcoin-core/secp256k1/blob/b97f7f5f9c3c8397a9cc77353803df4f926186f1/src/scalar_4x64_impl.h).
This reference was consulted for constant attribution after implementing the
value relation; no upstream implementation is copied. It is context, not proof
of the captured dependency revision, original symbol names or build provenance.

## Caller evidence and remaining closure

A whole `.text` E8/E9 pattern census of 83,719,936 bytes finds eight entry
references. Every site is independently decoded from its unique enclosing FDE
and confirmed at an instruction boundary. No E9 entry references were found.

| Entry | Direct call sites | Enclosing FDE starts |
| --- | --- | --- |
| A | `0x632afd4`, `0x632b6bf`, `0x632b6d5`, `0x632b841` | `0x632ae70`, `0x632b660` (twice), `0x632b7b0` |
| B | `0x63396ac`, `0x6339d9f`, `0x6339db5`, `0x6339f1e` | `0x63393a0`, `0x6339d40` (twice), `0x6339e90` |

The two storage-caller bodies use a null overflow pointer, whereas the paired
readers in `0x632b660` and `0x6339d40` use a stack dword. Retained instruction
contexts show the first overflow dword saved, then ORed with the second. This
explains the leaf's role in the existing signer chain without treating the
whole parser/recovery path as proved. This is not an indirect, short-jump,
alternate-entry or complete semantic xref census. No new crate/source ownership
or whole cryptographic dependency closure is inferred.

## Rust implementation and controls

[The Rust library](../../../src/node115-scalar-reduction/lib.rs) independently
uses a four-limb subtract/borrow chain, selecting the original value when the
subtraction borrows. Its safe API returns limbs and a Boolean. It does not
imitate the captured partial-register/carry instruction sequence or original
pointer ABI. There are no dependencies, placeholder modules or root workspace.
The pinned manifest/lockfile are actual inputs for this bounded library only.

Debug and release tests compare the new Rust against every frozen row. Two
clean release builds produce byte-identical local `.rlib` archives; this is
local reproducibility, **not target byte equality**. `fmt --check` and clippy
with warnings denied pass. [observed/build.json](observed/build.json) retains
commands, compiler/LLVM/linker versions, source/archive hashes and raw outcomes.

Controls include two actual encoded-immediate mutations, re-decoded below the
public identity gate only for counterfactual analysis: the low comparison
threshold +1 and reduction addend -1. Both yield **SAT** at input `n`, with
explicit replayed changed limbs/flag. A full-image same-size byte change fails
artifact admission. Two separate Rust source mutations (order low limb +1,
inverted overflow flag) compile and fail the frozen-corpus assertions. Neither
mutated target bytes nor any captured instruction is executed.

## Reproduce and verification limits

From the repository root on Linux x86-64, Python 3.13.12, Capstone 5.0.7,
pyelftools 0.32, z3-solver 4.15.4.0, GNU binutils 2.42, Rust/Cargo 1.95.0:

```sh
python3 research/work-items/RE-001-node115-scalar-reduction/analyze.py --output work/scalar-check
python3 -O research/work-items/RE-001-node115-scalar-reduction/analyze.py --output work/scalar-check-optimized
cmp work/scalar-check/records.json work/scalar-check-optimized/records.json
cmp work/scalar-check/boundaries.tsv work/scalar-check-optimized/boundaries.tsv
python3 research/work-items/RE-001-node115-scalar-reduction/disassemble.py --output work/scalar-disassembly
python3 research/work-items/RE-001-node115-scalar-reduction/build.py
make doctor
make verify catalogue-check
make reproduce
python3 -m unittest discover -s tests -p test_fde_extents.py -v
python3 -m unittest discover -s tests -p test_elf_index.py -v
```

Native disassembly receives an authenticated byte-identical read-only snapshot.
Only its transient path in the output banner is normalized. Python `-O` must
retain all admissions/proof checks. Existing static ELF/FDE tests pass (22).
Final command results and the full-suite limitation are in [VALIDATION.json](VALIDATION.json).

Full `make test` was not run: the existing
`tests/test_grow_family_panic_static.py:129` calls `behavioral()`, which at
`tools/grow_family_panic_static.py:948` maps captured instructions and invokes
them through ctypes. Its round-trip test also invokes that path. This session
has static-analysis authorization only; no test-runner or execution-policy
changes are included. No hosted-CI result is claimed.

Before this change, these two reader contracts and their overflow boundary
were unclosed in the retained chain. Afterward, the admitted leaf bodies have
an all-input static contract plus independently built, finite-tested Rust.
Original source/build identity, pointer aliasing, constant-time behavior,
compiled target identity, full caller semantics, curve operations and whole
node equivalence remain open. No byte-window registry entry or acceptance gate
is requested; all 92 full-scope gates remain false. Generated banner changes
count the new work item and source area only.

Next: close the normal/rejection paths of the paired compact-record reader,
then the arithmetic core behind the two storage callers, before claiming
complete signer/recovery behavior or the field producer's magnitude bounds.
