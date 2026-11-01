# RE-004: node94 BSR normalization in safe Rust

This reconstructs the complete numeric relation of one previously bound
48-byte foundation helper, including its word-independent flag bypass.
The new dependency-free `no_std` Rust fills the implementation gap in the
[static normalization packet](../foundation-bsr-normalize-94/README.md).
No component gate or target-code matching credit is requested.

- Component/task: foundation / bounded RE-004 arithmetic reconstruction.
- Target: Linux x86-64 node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Function: ELF VA `[0x55c9800, 0x55c9830)`, file offset `0x55c8800`;
  SHA-256 `5bd76530f7723cbf290d223bf5f62aa610256481f3f9a641e1fbff58733f5bb2`.
- Implementation: [lib.rs](../../../src/node94-bsr-normalize/lib.rs), with
  [input-only client](../../../src/node94-bsr-normalize/input_only_driver.rs).
- Authorship: new MIT Rust and mathematical fixtures; no can1357
  implementation was read or copied. Existing project-authored evidence
  and authenticated artifact bytes are the research inputs.

## Observed function and caller boundaries

The fresh admission checks the full target digest, all 48 body bytes,
the CIE, FDE and four retained direct calls. `.eh_frame+0x2d3cec` has
file offset `0xfb5204`, CIE offset zero and pcrel sdata4 encoding `0x1b`.
The decoded initial location is `0x55c9800`, extent `0x30`. The body has
returns at `0x55c9823` and `0x55c982f`; there is no padding before the next
FDE at `0x55c9830`. Its first instruction is `mov ecx,eax`, not `endbr64`.
The next FDE's existing boundary check is retained only by the old checker;
no neighboring body, behavior or implementation is claimed here.

The four direct call sites are `0x55cb6fb`, `0x55cb7f0`, `0x55cbde5`,
and `0x55cc00a`, all in caller FDE `[0x55caf70, 0x55cc408)` at
`.eh_frame+0x2d3dfc`. Fresh Capstone decoding covers its entire 5,272-byte
body as 1,201 linear instructions and confirms all four calls at actual
instruction starts with the expected relative targets. The caller body
hash and exact call bytes are in [ORACLE-FREEZE.json](frozen/ORACLE-FREEZE.json).
The old full `.text` `e8` byte-pattern scan and relocation-addend checks
also reproduce. These are not a complete xref census or caller CFG proof;
caller argument meaning and runtime reachability remain unknown.

Fresh GNU output includes the full selected helper and caller disassemblies
under `target-disassembly` / `caller-disassembly` in
`observed/raw-streams.json.gz`. The selected function/caller FDEs and CIE
are readable in [target.frames.txt](observed/target.frames.txt). GNU's
nearest-symbol annotations do not establish source attribution.

## Byte-derived relation and API boundary

Write `v`, `f`, `r` for the original low-u32 values of `RSI`, `RDX`,
and `RCX`. On the main path, `a` is the u32 value loaded from `[RDI]`.
The application meanings of all four inputs are unknown.

| Original ELF VA | Instruction relation | Consequence |
| --- | --- | --- |
| `0x55c9800` | `mov ecx,eax` | Save the original refinement selector before BSR overwrites ECX |
| `0x55c9802..0x55c9807` | Compare EDX with exactly 1; branch to `0x55c9824` | All other flag values take the main path |
| `0x55c9807..0x55c980f` | Load u32 `[RDI]`, add 1 in EDX, BSR into ECX | `n = (a+1) mod 2^32`; `k = floor(log2(n))` when `n != 0` |
| `0x55c980f..0x55c9818` | `EDI = k << 8`; test saved EAX | Start `base = 256*k`; original `r == 0` skips refinement |
| `0x55c9818..0x55c981f` | Shift EDX left 8 in u32, then logically right by CL; add to EDI | For `r != 0`, add `((n << 8) mod 2^32) >> k` |
| `0x55c981f..0x55c9824` | Move ESI to EAX, subtract EDI, return | Return `(v-base) mod 2^32` |
| `0x55c9824..0x55c9830` | Test original ECX, set nonzero byte, zero-extend, shift 8, return | Return 0 when `r == 0`, otherwise 256; no pointed-word load on this path |

The BSR result is `0..31` on its defined domain, so CL shift-count masking
does not alter that right shift. Its operand is 32-bit: widening the left
shift before right shifting is incorrect. The base is at most 7,937 on
admitted inputs; source nevertheless retains the observed u32 arithmetic
and explicit wrapping subtraction.

The API is a value projection:
`normalize(word: Option<u32>, value, flag, refinement) -> Result<u32, Refusal>`.
`Some(word)` supplies an already obtained numeric snapshot; it does not
claim to reproduce a pointer, alignment, load, memory lifetime or fault.
`None` allows callers to express that no snapshot was needed on the bypass.

`flag == 1` is tested first and returns `Ok(0)` or `Ok(256)` even with
`None` or `Some(u32::MAX)`. Otherwise `None` returns `MissingWord`, a new
safe-API refusal because a main-path value cannot be calculated without
the snapshot. `Some(u32::MAX)` returns `UndefinedBitScan`: the original
u32 increment would produce zero, for which BSR's destination is
architecturally undefined. This exclusion applies even when refinement
is zero, because the original main path still executes BSR. Neither
refusal is a recovered original error return. No behavior is invented
for original main-path BSR-zero inputs or bad pointers.

## Pre-Rust mathematical oracle

[oracle.py](oracle.py) froze its own source hash, static target/FDE/caller
facts and both fixture hashes before the new Rust source existed. The
compressed `frozen/inputs.tsv.gz` and `frozen/expected.txt.gz` retain those
exact decompressed streams. Admission and hash checks use explicit
exceptions and remain active under Python optimization.

The oracle finds the unique power interval `2^k <= n < 2^(k+1)` using
integer multiplication. It expresses the optional refinement as
`floor(256 * (n mod 2^24) / 2^k)`. Reducing modulo `2^24` before scaling
is equivalent to discarding the high byte during the original u32 left
shift. This quotient/remainder expression uses neither bit scans nor
shift instructions. A final residue modulo `2^32` supplies the result.
It is independently structured from the Rust leading-zero and shift
implementation, not target execution or an instruction emulator.

There are 16,237 distinct synthetic tuples: 16,015 numeric results,
100 missing-word refusals and 122 BSR-domain refusals. The corpus includes
4,617 bypass cases; every representable power-of-two BSR boundary and
adjacent incremented words; the `2^24` truncation boundary and varied
discarded top bytes; subtraction just below/at/above the base; flag 2
versus exact 1; high-bit nonzero refinement values; and a fixed-seed sample.
Both absent and MAX words are accepted on the bypass and rejected for
their distinct reasons on the main path. The full input domain is not
enumerated. Counts and named witnesses are in the freeze record.

## Native validation and controls

Only newly built Rust executes, on `aarch64-apple-darwin`. The pinned
compiler is rustc **1.94.1**, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8; Python is 3.14.3,
Capstone 5.0.7 and GNU objdump 2.47.20260726. The standalone rlib has no
external dependencies, Cargo manifest, build scripts or root workspace.
Its core library and the client's standard library are the installed
pinned compiler's components, not reconstructed target dependencies.

The validator uses edition 2021, `-Dwarnings`, `panic=abort`,
`overflow-checks=yes`, `debuginfo=0`, one codegen unit and a checkout-path
remap. Opt0 and opt3 each compile the library and input-only client twice.
All four runs match all 16,237 frozen rows: 64,948 comparisons, zero
mismatches. Repeat library, client and output hashes agree within each
optimization level. The client receives only the decompressed input TSV;
expected output is never passed to it or compiled into the library.

Each following wrong library was actually compiled at opt3, linked to the
same client and compared against the same frozen expectations:

| Deliberate wrong variant | Mismatches / 16,237 |
| --- | ---: |
| Widen the left shift before right shifting | 3,633 |
| Bypass on any nonzero flag | 5,826 |
| Reject MAX word before the flag bypass | 30 |
| Require a word before the flag bypass | 20 |
| Omit the word increment | 3,250 |
| Saturate the final subtraction | 4,660 |
| Arithmetic instead of logical right shift | 1,487 |
| Treat refinement as exactly 1 instead of nonzero | 5,582 |
| Test overwritten BSR rank instead of saved refinement | 2,489 |

For `(word,value,flag,refinement) = (16777215,8192,0,1)`, the correct
result is 2048; a widened left shift gives 1792. For `(0,1000,2,1)`,
the main path gives 744 while an any-nonzero flag bypass gives 256.
Absent/MAX word bypass cases make premature domain exclusions observable.
A separate one-row expectation corruption produces exactly one mismatch
against actual native output without modifying the frozen file.

[results.json](observed/results.json) retains counts, first mismatches,
source/build hashes and tool identities. [commands.json](observed/commands.json)
records exact command arguments and exit codes. One deterministic
`observed/raw-streams.json.gz` archive stores all original build/native
stdout and stderr bytes as base64, including empty streams; every stream
is bound to its command label and SHA-256. Only command paths are remapped
to `/repo`; raw streams are unchanged.

The existing focused normalization checker passed all 10 tests. Local
`make doctor verify catalogue-check reproduce` also passed with installed
GNU binutils first on PATH. Their combined stdout/stderr is retained in
`observed/repository-checks.json.gz`, with home/checkout paths redacted.
The final validator ran under `python3 -O`; 86 archived raw command streams
were separately decoded and checked against their recorded hashes.
No second full repository test sweep or hosted CI success is claimed.

Live overlap checks found no normalization/address conflict: 37 open PRs
at selection and 42 at the final check, with zero open issues. The distinct
BSR ladder PR #1389 covers `0x556e980`, not this helper. Final titles and
review/draft status are retained in [overlap-check.json](observed/overlap-check.json).
No claim, issue, external message or PR was created by this worker.

## Reproduce and limits

From the repository root with pinned artifacts materialized:

```sh
python3 tools/foundation_bsr_normalize.py \
  --check research/work-items/foundation-bsr-normalize-94/evidence.json
python3 -m unittest tests.test_foundation_bsr_normalize -v
python3 -O research/work-items/RE-004-node94-bsr-normalize-rust/validate.py
```

The validator defaults to `/opt/homebrew/opt/rustup/bin/rustc +1.94.1`
and `/opt/homebrew/opt/binutils/bin/objdump`; `--rustc` and `--objdump`
override executable paths while the compiler commit remains checked.
It writes native outputs below ignored `work/node94-bsr-normalize/`.
The retained invocation used
`--output research/work-items/RE-004-node94-bsr-normalize-rust/observed`.
Do not rerun `--freeze` after Rust exists; the guard prevents replacing
the pre-Rust expectations.

This is one helper's safe numeric projection. It does not establish the
original ABI, pointer behavior, caller integration, source provenance,
target x86-64 code identity or whole-component helper/data/relocation
closure. No normalization masks or compiled target-byte match are claimed.
Captured execution, instruction emulation, live node/chain actions,
unlicensed implementation copying and the neighboring helper were excluded.
Prior packets, imported evidence, pins and all progress gates are unchanged.
A remaining bounded question is how the four observed caller sites supply
the word and flags and establish the main-path BSR precondition.
