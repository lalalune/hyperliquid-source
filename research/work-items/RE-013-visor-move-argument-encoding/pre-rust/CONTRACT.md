# Proposed real Rust component and pre-code gate

This is the implementation phase of the **same unpublished six-body contribution**. The original `AUTHOR-FREEZE.json` and `MANIFEST.json` remain byte-for-byte unchanged, recording the earlier static phase. Root and a separate peer have cleared that phase. This document, oracle and frozen corpus precede all new Rust production source. A later implementation freeze will be distinct; no earlier receipt is restamped to imply it tested later code.

## Build and owned paths

Proposed component: `src/visor-move-request/`, with a real `Cargo.toml`, Cargo-generated dependency-free `Cargo.lock`, `src/lib.rs`, focused tests and README. No root workspace, registry dependency, build script, placeholder supervisor or graft into the unrelated `visor-large-request-class` numeric module. The production library uses safe Rust and standard allocation only. It has no subprocess, filesystem, environment, preflight, network or target execution interface. Its independent client may read synthetic input from stdin and write result bytes to stdout.

The already installed research rustc/cargo 1.94.1 for aarch64-apple-darwin is the proposed build toolchain; content hashes, complete version, linker identity, sysroot/build inputs and exact commands will be recorded before real builds. It is not the original Linux x86-64 Visor toolchain. Both unoptimized and optimized production builds, separately linked input-only clients, ordinary tests, raw own-build comparisons and compiling semantic mutants must run offline after the gate. Target machine-code equality, host allocation parity, original ABI and component completion remain unclaimed.

Only the new source directory and implementation additions under this packet are proposed. Existing proof/native evidence, shared tools, unrelated source, imports, catalogue/progress gates and byte-window registries remain unchanged. New evidence will bind to the original static freeze and this separate pre-Rust freeze.

## Chosen API and value contract

Proposed public operation:

`encode_admitted_move(source: &str, destination: &str) -> Result<MoveRequest, EncodeError>`

`MoveRequest` owns command bytes and provides `command_bytes() -> &[u8]` and `option_byte() -> u8`, the latter exactly **1**. These are newly chosen Rust names/types, not a recovered struct layout or native error object. The caller of this pure API supplies inputs **after externally admitting the opaque preflight**; this component does not call it or pretend to decide its predicate.

Valid Rust `&str` inputs enforce canonical UTF-8 and stable safe slices. A NUL remains legal in `&str` and must be rejected. The exact 25-scalar W set is explicit, rather than delegated to the host version of `char::is_whitespace()`. Empty/all-W operands are omitted. For any other operand, every original byte, including leading/trailing whitespace, is passed to the exact quoted-chunk grammar in PROOF.md. The operation joins the retained list `[b"mv", source?, destination?]` with one ASCII space in that order. No trimming, pathname normalization, argv splitting, option validation or general shell-escaping claim is added. Option 1 does **not** imply unconditional quiet wrapping; a quoted operand may contain `2>&1`.

Proposed error distinctions:

| New variant | Relationship to target |
| --- | --- |
| `EmbeddedNul` | Corresponds to the native mode-zero construction-error condition. It does not reproduce T/T+1 memory layout or the opaque error factory's RAX. |
| `LengthOutsideProofDomain` | A chosen safe refusal when the mathematical combined source length exceeds `2^61-2` or a host index conversion cannot be represented. It is not a target error code. |
| `AllocationFailure` | A chosen host-Rust `try_reserve` failure, with any retained standard error detail explicitly host-specific. No target allocator/OOM equivalence is claimed and no deliberate OOM is tested. |

The operation checks its chosen length domain and NUL condition before constructing bytes. This precheck order is a safe API policy, not a physical native allocation/error-order theorem. The target comparison covers the established ordinary successful allocation domain and the NUL no-request result. A host allocation failure is reported separately, rather than disguised as a target-grounded expected result.

A proposed pure companion `admitted_output_bound(source_len: u64, destination_len: u64) -> Result<u64, LengthOutsideProofDomain>` exposes the sufficient bound `4*(source_len+destination_len)+4` exactly when their mathematical sum is at most `2^61-2`. It is a chosen API for length admission, not an additional recovered native function. The production operation calls it before any `usize` conversion/reservation. Integer-only inputs exercise giant length boundaries without manufacturing invalid huge slices or attempting huge allocations. The actual supported build is 64-bit; no untested 32-bit allocation claim is made.

## Independent expected-value construction

The oracle reads and authenticates the same target artifact and original static freeze. It extracts raw/single/double/escape class constants and the W table from the actual captured byte coordinates, checking their exact pinned values. It does not import the static packet's `algebra.segments`, a Rust implementation, a shell parser or an instruction evaluator.

For an ordinary suffix, it independently finds the longest prefix admitted by **each** of the three languages (raw, single, double), takes the maximum length, and resolves equal lengths in raw/single/double priority. This equals the proof's longest prefix with a nonempty intersection: a prefix is admitted by the union of the three languages exactly when at least one individual language admits its complete prefix. The priority then chooses the same surviving least bit. A leading caret restricts the language to single quotes after consuming that initial caret exceptionally. The selected chunk is rendered by the explicit byte equations, then the remaining suffix is treated likewise. The intended Rust production algorithm instead maintains one shrinking mask in one scan; no production source exists at this gate.

The oracle is mathematical string processing, not native execution: no program counter, register/flag state, simulated memory, target dispatch or instruction stepping exists. Its formal connection to target bytes is the reviewed manual proof. Expected streams are independent of Rust output, but not an independently observed target runtime oracle. The corpus is finite and supports the all-input manual relation; it cannot replace that proof.

`inputs.tsv.gz` contains only case IDs and two input hex strings. `expected.tsv.gz` separately contains case ID, status and, on success, raw option byte 1 plus complete output hex. The production client must receive only the input stream. The parent comparator reads expectations and compares exact stdout; expected labels/hashes must never be supplied to the library/client. This is data-flow separation, not a claim that a filesystem sandbox hides expectations.

The corpus covers all ASCII one-/two-scalar combinations, the exact W set and neighboring nonmembers, UTF-8 length boundaries, quote conflict classes, leading/repeated/interior caret, NUL positions in either operand, absent operands, preserved surrounding whitespace, original operand ordering, quoted `2>&1`, and longer mixed strings. Separate integer-only length inputs/expectations cover the sufficient-domain edges and checked addition overflow. Category counts/hashes are retained; no desired answer comes from candidate Rust code.

## Required pre-code approval and later validation

Before writing Rust, the parent reviews this contract, oracle, source/target bindings and frozen input/expectation hashes. The expected corpus is generated twice in separate fresh output trees and compared without normalization. Small handwritten byte witnesses independently check the oracle, including caret boundaries and omission-versus-trimming. Changes after this freeze must be recorded as amendments, never silently treated as pre-code inputs.

After approval, required compiled mutants include trimming retained input, retaining blank inputs, missing NUL rejection, changed leading-caret state, swapped quote priority, consuming the conflict byte early, omitted backslash escaping, operand-order/separator changes and option byte 0. Actual mutant compilation and output mismatch evidence are required; a build failure is not semantic sensitivity. The code bridge must also explain safe checked lengths, original byte preservation and callback-free ownership without inferring original allocator behavior. Root/peer performs independent implementation and final evidence review before publication.
