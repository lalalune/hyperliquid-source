# Original-key hash results

Only authored Rust ran. No captured program, instruction evaluator, node traffic
or chain action ran. These finite native-derived mathematical comparisons do
not establish original machine-code identity, runtime behavior or a component gate.

## Freeze and native proof

- Historical pre-Rust freeze `frozen.json`: SHA-256
  `75381849673a9daaed5c0774f2103a65117989dc1e2b3c6c086f62e93d11cd9d`.
- Frozen fixture: 48 original-key cases, SHA-256
  `e201bf42560fe751d7ccb6d3fbd26bd67c4baab5e2a318d2b3e5132ad4193908`.
- Input-only stream: 4,375 bytes, SHA-256
  `4aba006c5437a90a868a370397cc2df219eea05af67fce198f867034c8880897`.
- Expected output stream: 1,639 bytes, SHA-256
  `26fe7e69b150d1d4c0417490f337890d301519af8197607df9a0a0c531358c4e`.
- Complete native proof binds 715 newly selected wrapper bytes plus 471 credited
  feed bytes, 324 contiguous GNU/LLVM instruction rows each, all three exact
  FDE/CIE/index records, identical 244-byte finalizers, six direct calls and
  caller seed-slot forms. The .data seed slot's zero file image and absence
  of targeting RELA entries are verified without inferring runtime values.
- Independent logical bulk and physical-order incremental equations agree for
  all 48 cases, 144 capacity-ignored projections, nine value substitutions,
  fifteen wrong-source/seed/delimiter controls and three fixed20 domain controls.
  All ten legacy full counter hashes for seventeen A bytes also agree.

## Actual compiled reconstruction

Official rustc 1.94.1, x86_64-unknown-linux-gnu, LLVM 21.1.8, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`; executable SHA-256
`ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`.
Eight source/input files and 68 selected compiler/std/linker files are hashed
before/after; dep-info closes the compiler-read project source set. This is not
whole-node compiler/linker/runtime provenance, including all system startup files.

- Qualifier: `python3 -I -B research/work-items/RE-001-key-hash-rust-94/verify.py --qualify work/key-hash-qualified-reviewed`, exit 0.
- Immutable source/input snapshot SHA-256:
  `ed02aa058465664501bc6bec91da1de04053e22e8aa6ae0da092f63e57703498`.
- Production lib SHA-256:
  `8b1d5e7913a5aa6dd588d75b62f04919c3dc7f020727d37c2a298498d20ee329`.
- Current candidate receipt `comparison.json` SHA-256:
  `1100279a07b9b024aaae12b1f9b6ab9b9dc24287645273544447db4359a4b918`.
- Baseline and seven source controls build at opt0/3: 16 builds/32 compiler
  invocations, all exit 0 with no diagnostics. Each baseline matches 48/48
  distinct native-derived expectations and all 192 u64 outputs (borrowed plus
  three copied-capacity variants; 1,536 numeric result bytes per profile).
- Four driver framing controls per baseline return exit 1 with empty stdout and
  exact expected stderr. This is harness behavior, not native refusal behavior.

| Compiling semantic source mutation | Differing paired cases per profile |
| --- | ---: |
| Wrong seed lane | 32 |
| Omit supplied seed | 32 |
| Omit delimiter | 48 |
| Replace delimiter ff with fe | 48 |
| Hash alias letters instead of original key | 48 |
| Append alias producer's counter zero | 48 |
| Truncate key at sixteen bytes | 30 |

Source mutants come from the fixed reviewed source, and actual output is compared
against independently frozen bytes. Expected answers are never supplied to the
input-only Rust driver. All first raw witnesses and stdout hashes are retained.
The text bundle has 132 allowlisted inert members; decoded payload 8,033 bytes,
SHA-256 `95fa748796847f393b05b2458d81ea172c68e97dce8e08a7b15000b9cbd639a5`.
No executable, rlib/object, copied source or captured artifact bytes are encoded.

The first verifier guard refactor had an IndentationError before compilation;
it was corrected and the complete qualifier rerun successfully. Earlier local
qualification receipts remain ignored; only the exact current verifier receipt
above is the candidate. No failed or earlier run is relabeled as final evidence.

## Existing component and inline requalification

Locked/offline Cargo build/test commands pass in debug/release, all exit 0;
each profile runs five tests. Original 78 aliases/780 counter hashes/1,056 feed
states and 156 inline native rows/two API refusals remain covered, plus the new
48 key-hash cases. Actual commands/stdout/stderr and source pins are retained
in `component-builds.json`. Manifest/lockfile and dependencies are unchanged.

The old inline receipt/source snapshot remains historical at published commit
`743257a699da958290d18dd89825c7a1804f58b8`; its receipt SHA remains 578af8b4…cebd3.
The changed-source inline requalification has its OWN receipt
`80cfc156737cb03c65d3b92b447eff60b64e3968ec67fd9d7c03d91403a3c355`:
15 builds, original 156+2 rows and six source mutants, with repeated own opt3
products equal. See the inline packet's `historical.json` and separate current
RESULTS section. Those 156+2 cases are not counted as new key-hash cases.

## Final exact-tree checks

- New focused native/equation/retained-stream tests: 8/8 normally (7.681 s)
  and 8/8 under Python `-O` (4.252 s), exit 0 each. The initial `-O` pass found a stale
  documentation digest after a README edit; the manifest was refreshed and the
  complete focused group rerun successfully. No semantic test failed.
- Existing inline focused tests: 9/9 normally (2.240 s) and under `-O`
  (1.755 s), exit 0 each, including the fresh current-source receipt/bundle.
- `make doctor`, standard invocation-local LFS-filter `make verify`,
  `make catalogue-check`, and `make reproduce`: all exit 0. Doctor reports
  analysis ready and exact rebuild not ready. Three target signatures, 38
  imported files and all seven pinned reference repositories verify.
- Static verifiers for both packets pass normally and under `-O`, exit 0
  each; both scoped manifests pass 14/14, and `git diff --check` exits 0.
  No input, import, submodule pin or persistent filter is changed.

Logs: `/tmp/key-hash-{doctor,verify,catalogue,reproduce}.log`,
`/tmp/key-hash-focused.log`, `/tmp/key-hash-focused-opt-final.log`,
`/tmp/key-hash-inline-focused{,-opt}.log`, and
`/tmp/key-hash-qualify-reviewed.log`.

No new full-suite run on this head is claimed. The coordinator's separate
baseline attempted 972 child files and failed 22 child files for environment
fixture reasons (make exited 2). The supplied toolchain has no rustfmt/clippy;
neither was installed or claimed.

Runtime seed values/provider/lifetime, cache slot reachability, allocator/copy/
free/source preservation, locking, equal-key replacement/deallocation, display,
original ABI, faults/unwind and whole constructor/component gates remain open.
