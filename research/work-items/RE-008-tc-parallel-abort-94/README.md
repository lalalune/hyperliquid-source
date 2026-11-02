# RE-008: TC parallel verification abort and error reduction

The native TC verifier does not simply check every vote in index order and
return the first error. A shared byte can stop work before a task begins or
after a successful local check. The local folder retains an existing error;
the bridge selects the left child when both supplied child results failed
and delegates the right error to cleanup. That local precedence does not
establish a global first-invalid-index rule.

This closes a concrete gap left by the index-order stub documented in
`research/work-items/RE-008-block-admission-94/README.md` and the existing
`src/node94-consensus-admission/README.md`. Those packets' signature and quorum
findings are credited. Their files and APIs are unchanged.

Task/component: RE-008 / consensus. Analysis base:
`e5c9b6436876b2a4a39daef813171f9879317699`; rebased onto
`2c75904241b9165693d40dea8b0d0d340f8e22b3` after the broad upstream merge. Target: Linux x86-64 node #94,
91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Coordinates are linked ELF virtual addresses, with exclusive ends.

| Role | Complete FDE range | Bytes / instructions |
|---|---|---|
| Split/abort/merge bridge | `0x4768f80..0x47694d3` | 1,363 / 252 |
| Sequential signature-result fold | `0x476f3e0..0x476f6ed` | 781 / 169 |
| Selected subject total | two complete FDEs | 2,144 / 421 |

Nine additional complete context bodies bind the real caller, timeout verifier,
cleanup, join/runtime boundaries and callback. Together with the subjects,
GNU and Apple LLVM agree with Capstone on all 8,120 bytes / 1,742 instruction
boundaries. They are context, not nine new algorithm claims. The full E8 scan
finds five confirmed direct incoming sites; no RELATIVE relocation has a
subject start as its addend. This is not complete indirect reachability.

The caller initializes the cancellation byte to zero, uses a minimum chunk
length of one, and reaches signer collection/quorum only after the bridge
returns its success tag. The local fold clears ECX before calling the timeout
verifier, so it skips re-verifying that vote's nested QC. It does not itself
test cancellation before its first call. Both-success merge writes only the
eight-byte tag; a selected error writes its full 80-byte supplied record.
`PROOF.md` gives the native sites, admitted domain and universal local argument.

## Licensed source and implementation scope

Rayon 1.10.0's published `try_reduce.rs` and `plumbing.rs` independently explain
the folder, shared cancellation, split-budget and left/right reduction
structure. The target contains Rayon 1.10.0 / rayon-core 1.12.1 source-path
strings. Official tag v1.10.0 resolves to commit
`7543ed40c9a017dee32b3dc72b3ae819820e8366`; `sources/acquisition.json` pins the
exact selected files and both upstream MIT/Apache notices.

This is structural correspondence, not recovered crate-lock, source-patch,
compiler or compiled-byte identity. In particular, the public source's
Relaxed atomics cannot be uniquely inferred from the ordinary x86 byte MOVs.
The private error/closure types and transitive scheduler effects remain open.
No source-built Rayon byte comparison or code-window credit is claimed.

`rust/` is a real standalone, dependency-free analysis crate, with an unsafe
code ban. It projects the local fold from supplied verifier outcomes and
observed cancellation bytes, merges supplied child results, and reports one
bridge decision from supplied length/split/worker observations. It does not
replace Rayon or expose an authenticated consensus API. The native relation
requires valid disjoint stable storage, ordinary noninterfering helpers and
defined projected bytes. It deliberately does not assign values to inactive
native enum payload bytes. Numeric wrapping pointer deltas are not mapped
pointer admission. The raw tag/byte domain includes locally meaningful states
that the ordinary typed caller need not produce.

## Qualification

The independent oracle uses a least-terminal-index set, merge truth table and
disjoint integer regions. It and all 6,780 cases were frozen before the Rust
directory existed: 3,500 fold, 144 merge and 3,136 bridge observations. The
driver only consumes inputs; expected outputs are never passed to it.

Actual Rust 1.94.1 host runs, using fresh output paths:

- opt0 and opt3, each repeated: all 27,120 observations match; both rlib and
  client bytes match within each same-profile repeat after the declared path
  remap.
- All 22 compiled opt3 semantic mutants exit normally and produce mismatches.
  These test the conditional projection, not patched captured execution.
- Four actual-stream comparator corruptions are rejected. Eight parser inputs
  (including the accepted empty input) and an extra-argument control have the
  required statuses.
- Eight focused static test methods pass under `python3 -O`, including 36
  corrupted target/anchor/whole-body/relocation/FDE/jump-table controls below
  the appropriate identity guards.
- The 53 existing consensus-wire/timeout-transition tests pass with GNU
  binutils on PATH. An earlier run passed 49 and skipped four GNU-only checks;
  that incomplete cross-check remains recorded.
- `make doctor verify catalogue-check reproduce` passes. The actual standalone
  Cargo graph passes pinned, offline/locked Clippy for all targets with warnings
  denied. No full repository test sweep, hosted CI or runtime node test is
  claimed on this contribution head.

`native/result.json` retains all 88 commands and compiler/artifact identities.
All 176 exact stdout/stderr streams are losslessly retained in
`native/raw-streams.json.xz`. Repacking the original gzip JSON to xz reduced
13,498,853 bytes to 510,536 bytes without changing any of its 33,890,564 raw
JSON bytes. `native/repack.json` binds both forms; original gzip/raw files and
compiled artifacts remain in ignored work. No native run was recomputed for
packaging. Validation-log path normalization is separately documented in
`validation/log-index.json`; native streams and fixtures are unchanged.

Development failures are retained: the first collector omitted the legitimate
`0x47328da` drop-table target and rejected the table; the corrected expectation
preceded the oracle freeze. Source acquisition first failed in the restricted
network environment, then succeeded through approved official GitHub API reads.
Neither failure is reported as a passing comparison.

The latest-base checks are separate in `validation/new-base-checks.json`: all
61 selected tests, retained packet replay, and `make doctor verify
catalogue-check reproduce` pass. The rebase first failed on an unavailable LFS
object, then on files left by that partial checkout. Every such file was matched
to the new base and moved to ignored quarantine without deletion; command-local
skip-smudge allowed rebase. The first new-base manifest check rejected LFS
pointers; hydration from the shared local cache fixed that admission failure.
Original failures and final successful logs are retained separately. Source,
oracle and frozen corpus did not change, and native runs were not repeated or
relabelled as post-rebase experiments. No full suite on the new head is claimed.

## Reproduce

From the repository root, with the pinned target and installed Python/Capstone:

```sh
python3 -O -B research/work-items/RE-008-tc-parallel-abort-94/verify_packet.py
python3 -O -B -m unittest tests.test_tc_parallel_abort94 -v
python3 -B research/work-items/RE-008-tc-parallel-abort-94/export_disassembly.py \
  --gnu /path/to/gnu-objdump --llvm /path/to/llvm-objdump --out NEW_DIR
python3 -O -B research/work-items/RE-008-tc-parallel-abort-94/validate_native.py \
  --toolchain-bin /path/to/rust-1.94.1/bin --out NEW_DIR
```

Both output directories must be new. `verify_packet.py` checks the exact
manifest, re-derives static records and the frozen mathematical oracle, and
replays all retained normal/mutant output comparisons. `validate_native.py`
compiles and executes only newly authored Rust, emits its original gzip
archive format, and does not execute a captured binary or an instruction
emulator. The host OS/SDK is not hermetically pinned; this is semantic host
qualification, not an x86 target build.

`research-handoff.json` records three bounded claims, the primary source URLs,
counterchecks and limits on independent external support. `overlap.json` keeps
the supplied pre-work inventory snapshot and its time/coverage limits; it is
not a claim about later GitHub state. Analysis and new code by 신준; coordinator
attribution: `openai/gpt-6-astra / Codex 0.166.0`.

No component gate changes. Network services, keys, signing, chain actions,
captured execution, arbitrary native aliases, unwinding, atomic-order identity
and complete parallel verification remain outside the result.
