# RE-004: independently reconstruct the node94 divide-then-log2 bucket

- Component: foundation; bounded arithmetic reconstruction.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source base: current `origin/main`, freshly fetched at
  `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Included: the complete 114-byte FDE `[0x4f9eb10,0x4f9eb82)`, internal NOPs,
  external padding and successor extent, full caller byte/FDE binding, observed
  divisor setup, safe Rust value API, proof and independent native checks.
- Reference: project-authored
  [foundation-divide-then-log2-bucket-94](../foundation-divide-then-log2-bucket-94/README.md).
  No unlicensed inferred implementation was read or copied.
- Excluded: original source/library names, caller purpose, original ABI/trap
  handling, full caller control flow, compiled target identity and full gates.

The prior packet expressly excluded Rust reconstruction. This change implements
the complete normal-return relation for every u64 dividend and nonzero u64
divisor, while making zero-divisor refusal explicit in a newly chosen safe API.
It is distinct from the BSR bucket at `0x556e980`; no common library or purpose
is asserted. Existing evidence, pins and progress counters remain unchanged.

Before work on 2026-11-02 KST, live inspection found 45 open PRs, zero open
issues and no matching address/topic claim. Current `src/` had no implementation.
The coordinating agent reserved this scope. No issue or external claim message
was created by this worker.

## Revalidated code, FDE and caller

Coordinates are linked ELF virtual addresses. The leaf begins at file offset
`0x4f9db10`; its full-body SHA-256 is
`6a5f51de0418a80d23313f6f8c849a6058bff5676858fa9a292cd9266b5b5011`.
`verify_static.py` admits only the full target digest, parses the actual ELF
and complete FDE table, requires exactly one overlapping leaf FDE and stores
the selected FDE/CIE records. The leaf has no LSDA. Fourteen `int3` padding
bytes end at successor `0x4f9eb90`, whose FDE ends at `0x4f9eba5`.

Fresh GNU and Apple LLVM exports agree on all 37 leaf instructions and every
byte, including the 10-byte, 5-byte and 2-byte NOP sequences between return
blocks. These 17 internal padding bytes are part of the 114-byte FDE, not
external padding or a smaller selected denominator. No instruction bytes are
masked. All five conditional targets are checked against instruction starts.
The arithmetic cap is locked separately: `shr 6; setne; movzx; add 5; ret`.
There are no leaf calls, data loads, tables or external jumps. The memory-like
NOP operands do not access memory. A valid return stack is assumed.

The full caller `[0x4f9cf20,0x4f9d393)` is retained and byte-checked in both
disassembly exports, with its unique overlapping FDE and CIE. GNU has 274
instructions; Apple LLVM prints 280 rows because it separates six `LOCK`
prefixes at `0x4f9d267`, `0x4f9d27d`, `0x4f9d28c`, `0x4f9d2b9`, `0x4f9d2c5`
and `0x4f9d2d1`. The checker joins only those single-byte `f0` rows to their
contiguous next rows and then requires exact agreement with GNU. This is an
explicit printer-row grouping, with no byte changes or masking; the original
exports and all joined addresses remain recorded. The selected argument chain
does not contain any such split prefix and agrees directly.

That chain starts at `0x4f9d21d`: `mov esi,0x80000` zero-extends RSI, then
`mov rdi,r14` sets the dividend. Five RBP-relative stores follow; none writes
either argument register. The call at `0x4f9d240` is an actual instruction
start and its rel32 resolves to `0x4f9eb10`. The complete `.text` e8 scan finds
only that candidate. This establishes the observed divisor, not the purpose
of R14 or a complete indirect/tail-call census.

All ELF RELA records are scanned for writes overlapping the selected leaf,
padding or caller and for addends naming the leaf entry. None occurs. The
overlap check conservatively uses eight bytes per record; it does not infer
unknown relocation widths. No read-only data constant needs binding here.

Raw export commands, from repository root:

```sh
/opt/homebrew/opt/binutils/bin/objdump -d --insn-width=16 --start-address=0x4f9eb10 --stop-address=0x4f9eb82 artifacts/node/94/hl-node
/usr/bin/objdump -d --start-address=0x4f9eb10 --stop-address=0x4f9eb82 artifacts/node/94/hl-node
/opt/homebrew/opt/binutils/bin/objdump -d --insn-width=16 --start-address=0x4f9cf20 --stop-address=0x4f9d393 artifacts/node/94/hl-node
/usr/bin/objdump -d --start-address=0x4f9cf20 --stop-address=0x4f9d393 artifacts/node/94/hl-node
```

## Proof, new API and independent expectations

[`PROOF.md`](PROOF.md) derives the result directly from the bound instructions.
RDX is zeroed before unsigned DIV, so the 128-bit dividend is exactly the raw
u64 RDI value. For every nonzero divisor, the quotient fits in u64. The five
shift tests each start from the original quotient; the final cap uses a boolean
plus five. The returned RAX word is zero-extended and always in 0..6.

`bucket(u64,u64) -> Option<u8>` is a new Rust API, not an original type or ABI.
It returns Some(0) for quotient 0 or 1; otherwise it computes the integer log
using leading zeros and caps it at six. No unstable floating math, dependency,
unsafe code or generated implementation is used. Every operation is range-safe.

The target has no normal return when divisor=0, including dividend=0. The
Rust function returns None before division. That refusal is separately tested
as new API behavior; zero-divisor rows do not pretend to supply target returns
or replicate hardware exceptions. Physical registers, flags, trap handlers,
unwind/CET behavior and the complete caller are outside this value projection.

Before writing Rust, the static producer froze 9,892 input pairs and expected
two-byte API records. For positive divisor d it counts the true comparisons
`dividend >= (2^k)*d` for k=1..6 using unbounded integer products. It never
divides, calculates a bit length/logarithm or runs an instruction evaluator.
The threshold equivalence to the captured quotient rule is proved separately.

There are 9,702 normal-return cases across all seven buckets and 190 newly
defined zero-divisor refusals. Divisors cover powers-of-two and neighbors,
high bits, maximum u64 and the observed `0x80000`; quotient thresholds and
remainders straddle each bucket edge. Forty-nine pairs use the observed caller
divisor. Another 1,024 pairs come from deterministic SHA-256-derived words.
Products exceeding u64 remain exact in the oracle instead of wrapping.
`coverage.json` records bucket counts and input/expectation hashes.

The separate native client consumes only `(u64 LE,u64 LE)` input pairs. It emits
`[0,0]` for refusal or `[1,bucket]` for admitted inputs. Those two-byte records
are a new validation protocol. The client embeds no expectations and opens no
files. Its parent owns the frozen expected bytes and compares complete output
records. This is data-flow separation, not a filesystem sandbox.

## Reproduce

From repository root with the pinned captures and submodules materialized:

```sh
PATH="/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH" make doctor
make verify catalogue-check reproduce
python3 tools/foundation_divide_then_log2_bucket.py --check research/work-items/foundation-divide-then-log2-bucket-94/evidence.json
python3 -m unittest tests.test_foundation_divide_then_log2_bucket -v
python3 -B research/work-items/RE-004-divide-bucket-rust-94/verify_static.py
RUSTC_BIN=$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)
python3 -B research/work-items/RE-004-divide-bucket-rust-94/verify_rust.py \
  --out work/divide-bucket-review --rustc "$RUSTC_BIN"
shasum -a 256 -c research/work-items/RE-004-divide-bucket-rust-94/MANIFEST.sha256
```

The freeze command refuses to overwrite records; ordinary verification
regenerates and byte-compares both frozen archives and the static/coverage
records. Native output directories must also be new.

Recorded tools: Python 3.14.3, GNU objdump 2.47.20260726, Apple LLVM/clang 17.0.0
(`clang-1700.0.13.5`), macOS 27.0.1; rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8, explicit target and
host `aarch64-apple-darwin`. The verifier enforces actual rustc SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The linker hash/version is recorded; every OS SDK or compiler shared library
is not pinned. This is research build provenance, not the original Linux build.

The direct dependency-free rustc build uses edition 2021, one codegen unit,
opt0 or opt3, overflow checks, denied warnings, explicit `/usr/bin/cc` linker
and repository path remapping. No Cargo workspace or invented lockfile is
needed. Only newly authored native Rust is executed.

## Observed results

Each optimization level passed all 9,892 comparisons and three Rust unit
tests. Repeated rlibs and linked clients were byte-identical at both levels:
four own-build comparisons, no byte normalization. The common output SHA-256 is
`8f2626ce4c467b0a38dc69168f3cc49f65696b7d02cd71d2dad6231dfb0cb637`.
Partial inputs of 1 and 17 bytes were rejected before any output in both builds.

Eight wrong implementations were compiled and executed at each optimization
level, exited normally and were rejected by output differences:

| Wrong implementation | Mismatches per optimization |
| --- | ---: |
| Signed division | 682 |
| Dividend narrowed to 32 bits | 4,402 |
| Divisor narrowed to 32 bits | 3,995 |
| Zero divisor accepted as bucket zero | 190 |
| Cumulative shifts instead of fresh quotient tests | 6,457 |
| Cap at five | 2,199 |
| No effective cap (maximum 63) | 673 |
| Quotient two treated as bucket zero | 643 |

The signed mutant uses wrapping signed division for its MIN/-1 pair. The
narrow-divisor mutant substitutes one when narrowing would yield zero. These
deliberate controls expose wrong values without mistaking an overflow/division
panic for a successful semantic comparison. They are not alternative target
implementations. Changed and missing output records also exercise the comparator.

Eleven below-digest structural controls reject changed high-dividend zeroing,
unsigned DIV, cap shift/condition, internal NOP, padding, both FDE extents,
caller divisor, intervening store and call edge. The existing static checker
and seven focused tests passed. Two hash-seed/time-zone regenerations reproduce
the frozen evidence exactly. Completed repository results are in `checks.txt`;
the full repository test suite and hosted CI are not claimed by this worker.

`native/calls.json` preserves commands, statuses, stdin and raw stream hashes;
only repository/compiler paths use `<repo>` and `<rustc>` placeholders.
`native/results.json` binds sources, fixtures, actual tools, repeat artifacts
and first mutation witnesses. A single deterministic `raw-streams.json.gz`
maps stream filenames to hashes and stores each base64 payload once. Decoded
streams were checked byte-for-byte against raw output. Input and expectation
archives have separately frozen hashes.

## Limits

No captured node, instruction emulator, unlicensed inferred implementation,
instruction transplantation, keys, chain activity or networked node was used.
Full-domain returned-value reasoning is separate from finite native regression
tests. Original ABI/compiler/byte identity, source labels, caller meaning and
whole-component gates remain unresolved. The next unanswered question is how
the observed caller interprets the bucket and constrains R14; this packet does
not extend into that caller's larger behavior.

Execution provenance: OpenAI via Codex; the exact model identifier was unavailable
to this worker and is not guessed.
