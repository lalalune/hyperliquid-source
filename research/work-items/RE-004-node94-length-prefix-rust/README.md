# RE-004: node94 length-prefix leaf with overlapping payload memory

This contribution independently reconstructs the complete 106-byte leaf
`[0x55716a0, 0x557170a)` as a dependency-free `no_std` Rust memory projection.
It resolves the Rust gap left by the
[foundation packet](../foundation-length-prefix-encoder-94/README.md), including
the previously unmodeled effect of payload/output aliasing. Target node #94
is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.

The output consists of a length-dependent header and one payload byte.
The target stores the header before reading the payload. In the large path
it stores a four-byte header and then overwrites the fourth byte with the
payload; an alias to that fourth byte observes the stored header value.
The result cannot in general be recovered from an unconditional entry-byte
snapshot. The new safe API models either a stable disjoint byte or an index
into the mutable output slice, preserving that ordering explicitly.

## Scope, evidence, and bounds

The [proof](PROOF.md) derives the complete three-path partition, little-endian
byte digits, u32 modular arithmetic and alias-aware memory substitution for
every u64 length. It also proves that every successful safe-API index is in
bounds, all refused calls leave memory unchanged, and all successful calls
leave the slice suffix unchanged. `OutputTooShort` and
`PayloadOutsideOutput` are new safe-API refusals for unsatisfied memory
premises; they are not target returns or modeled target faults.

Static admission rechecks the complete target digest, full leaf bytes, CIE,
FDE extent, six padding bytes, and the complete 1,529-byte caller at
`[0x55739f0, 0x5573f89)`. Capstone 5.0.7 linearly decodes all 30 leaf and
327 caller instructions. GNU objdump independently retains both complete
bodies and selected frame records. Call `0x5573e2b` is an actual decoded
instruction whose immediate setup is RDX=R10 and RDI=R12; RSI is loaded
but unused by this leaf. The existing checker also reproduces its direct-e8
and relocation scans. The caller's wider behavior and RCX's meaning are
not reconstructed. The leaf has no callees, tables or relocated constants;
all its immediate constants and memory accesses are included.

`frozen/ORACLE-FREEZE.json` binds the exact pre-Rust oracle source, original
static facts, and uncompressed fixture hashes. The freeze was created at
`2026-11-01T19:59:10.590675+00:00`, before the new `lib.rs` existed; its
creation code refuses to run after Rust exists or overwrite a prior freeze.
The oracle source was not subsequently changed. It computes unbounded
integers, base-256 quotient/remainder digits and memory-map substitution,
independently of the Rust's u32 arithmetic and slice writes. It does not
interpret instructions or execute captured code.

Only `src/node94-length-prefix/` and this packet are new. No imported source
implementation was read or copied. Prior evidence, pins, component gates
and generated catalogues are unchanged. New code and prose use the root
MIT license; captured bytes and disassembly retain the artifact's rights.
The live overlap check found no match among 57 open PRs (including drafts
and review state), zero open issues, or 20 recent merged PRs. The inventory
is retained in `overlap.json`; `src` had no implementation of these
addresses or length-prefix semantics before this change.

## Observed native validation

The input-only driver receives length, initial output bytes and payload
source. It has no expected outputs, oracle dependency or target-file access.
Only newly compiled Rust runs. The validator compares complete returned
status/count and every supplied output byte externally.

There are 74,880 frozen cases: 31,288 successful memory projections
(1,280 short-path, 1,814 medium-path, 28,194 large-path), 33,548 short-buffer
refusals and 10,044 out-of-slice refusals. Cases cover every n from 0 to 65,
both thresholds, powers of two ±2 across u64, wrap/sign edges, all 256
external byte values at 12 selected lengths, every possible fourth-header
byte, header/payload/tail aliases, invalid indices and 1,024 deterministic
additional lengths. Initial slice sizes are 0, 1, 2, 3, 4, 5 and 8.
The finite fixtures supplement the full-domain proof, not an exhaustive
enumeration of all u64 values or all memory states.

Installed rustc 1.94.1 (`e408947bfd200af42db322daf0fadfe7e26d3bd1`,
LLVM 21.1.8) builds the standalone library and driver at opt-level 0 and 3,
twice each. All four builds match every frozen case: 299,520 row
comparisons, zero mismatches. Repeated library, client and stdout hashes
match within each optimization level. These are aarch64-apple-darwin native
builds on macOS 27.0.1; cross-host binary reproducibility and x86 ABI
equivalence were not measured. Python 3.14.3 ran the validator under `-O`,
so evidence checks do not depend on Python assertions.

Eleven incorrect Rust variants are actually compiled and run against the
same input-only driver. Each gives nonzero observed mismatches:

| Variant | Mismatched rows |
| --- | ---: |
| First threshold exclusive | 282 |
| Second threshold exclusive | 279 |
| Narrow to u32 before first branch | 3,456 |
| Signed first branch | 14,456 |
| First-path multiplier 16 | 1,000 |
| Medium tag 13 | 1,814 |
| Large tag 5 | 28,194 |
| Omit fourth header byte store | 4,598 |
| Big-endian header | 31,288 |
| Read payload before writing header | 19,055 |
| Overwrite untouched suffix | 23,230 |

The fourth-store mutation fails, for example, for n=4096 with initial
`4c7196bb` and payload offset 3: correct `0d000100`, mutant `0d0001bb`.
The early-read mutation fails for n=0, initial `264b`, offset 0: correct
`0101`, mutant `0126`. These controls expose actual ordering differences.
Replacing one frozen expected row in memory gives exactly one mismatch
against an actual unmodified native output. Eleven independent structural
corruptions bypass the full-file digest and are rejected by body, caller,
CIE/FDE or padding checks. They include changed instructions and a caller
byte beyond the old retained excerpt. The original target is never altered.

## Reproduction and retained output

From the repository root, with pinned artifacts materialized and installed
Python/Capstone, rustc 1.94.1 and GNU objdump:

```sh
python3 -B -O research/work-items/RE-004-node94-length-prefix-rust/validate.py
python3 -B -O research/work-items/RE-004-node94-length-prefix-rust/verify_recorded.py
python3 -B tools/foundation_length_prefix_encoder.py --check research/work-items/foundation-length-prefix-encoder-94/evidence.json
python3 -B -m unittest tests.test_foundation_length_prefix_encoder -v
env PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
shasum -a 256 -c research/work-items/RE-004-node94-length-prefix-rust/MANIFEST.sha256
```

`validate.py` accepts `--rustc`, `--objdump`, and `--output` overrides; the
compiler version/commit remains checked. Its default output and native
builds stay in ignored `work/node94-length-prefix/` (about 12 MiB in this
run). Frozen `.gz` fixtures and observed archives require normal Git LFS
materialization under the repository's existing attributes.

`observed/results.json` records source/build/output identities and concrete
control counterexamples. `observed/commands.json` records exact arguments,
exit status and stream hashes, using `/repo` for the worktree path.
`observed/raw-streams.json.gz` retains 98 exact stdout/stderr streams as
base64 with raw SHA-256 values. Decompression, every hash and every actual
native mismatch count are independently rechecked by `verify_recorded.py`.
The large GNU frame stdout is deliberately excerpted separately in
`observed/target.frames.txt`; the frame command's retention policy says so.
`observed/static-controls.json` records all structural rejections.

`make doctor verify catalogue-check reproduce` passed. The legacy evidence
checker and its 12 focused tests passed. `observed/repository-checks.json.gz`
retains those logs; repository log paths are redacted as `/repo` and
`<home>`, with original and retained hashes labeled separately. The focused
commands were repeated once solely to retain their complete raw output.
No duplicate full repository test sweep was launched; the coordinator's
separate full run is not claimed as a result of this packet. Hosted CI,
captured execution, target-byte matching, complete caller reconstruction
and component gate completion remain unmeasured or out of scope.

Authorship tooling: OpenAI / Codex. This runtime does not expose an exact
model identifier; none is invented here.
