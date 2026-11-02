# Observed inline-carrier results

The historical sections below concern the existing authored alias component and the
explicit admitted native projection. No captured program, emulator or captured
instruction evaluator ran. No hosted CI, container, original ABI/machine-code
identity or complete-constructor/component gate is claimed.

## Historical compiled comparison at 743257a6

- Official rustc1.94.1, host x86_64-unknown-linux-gnu, LLVM21.1.8, commit
  `e408947bfd200af42db322daf0fadfe7e26d3bd1`.
- Compiler executable SHA-256:
  `ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`.
- 68 selected compiler/std/linker provider files and seven project source/input
  files are hashed before/after. This does not claim the missing whole-node
  compiler/linker/runtime provenance.
- Fixed source/input snapshot SHA-256:
  `a965a70b02366c17b069cb44bb02782af0aaec885f61a85a60240ee90d222db7`.
- Qualifier: `python3 -I -B research/work-items/RE-001-inline-carrier-rust-94/verify.py --qualify work/inline-carrier-qualified`, exit0.
- 15 builds, 30 compiler invocations, all exit0 and zero diagnostic bytes.
  Baseline and six source controls compile at opt0/3; baseline opt3 is repeated.
- Each baseline matches 156/156 native rows (all2,496 carrier result bytes,
  low/high halves separately) and both API-only refusal rows. Four malformed
  driver framing controls return exit1 with the exact expected stderr and
  empty stdout on each baseline build.
- Repeated authored opt3 library and executable hashes are raw byte-equal.
  The compiler receives one explicit authored build-path remap; no captured
  or generated machine-code bytes are normalized. This is host repeatability,
  not original-binary identity.

| Compiling source control | Native differing cases per profile | API-only differing cases |
| --- | ---: | ---: |
| wrongly exclude length16 | 132 | 0 |
| reverse byte order | 145 | 0 |
| shift7 instead of8 | 138 | 0 |
| sign-extend source byte | 34 | 0 |
| exchange low/high64 | 150 | 0 |
| return Some0 above16 | 0 | 2 |

The first five controls are operative on admitted native inputs. The last
tests only chosen API behavior and is not native-domain coverage. Complete
actual stream hashes and first raw witnesses are in `comparison.json`.
That unchanged receipt SHA-256 is
`578af8b4edd5fcd4c1ee58dbe210b6af972476d93f4746d53d0fd25cc29cebd3`.
The text bundle's decoded payload SHA-256 is
`d32a51613ef879a0088a75b062d90bf406929923cbc3b0b34f2ab6ef7acb1736`.
The original full archive remains ignored/private; its SHA-256 is
`f7d9ccd445d7b29e1eac1e68b3836b127c3f5d110baadd8fae41f994d3794a77`.
Text encoding removes duplicate source/native-context files from the retained
bundle and changes no prior actual input/output byte or hash.

## Historical component and static checks

Actual locked/offline Cargo debug/release builds and debug/release tests all
exit0. Each profile runs four tests, including all new156+2 rows and unchanged
78 aliases/780 counter hashes/1,056 streaming states. `component-builds.json`
retains exact commands, stdout/stderr and unchanged source/input hashes.
No manifest, lockfile, dependency or build script is fabricated or changed.

The complete native identity, 156 width-explicit equations, two separate API
cases and five operative native operand controls pass. Static control mismatch
counts are132,145,74,138,2; their normal-return/selected-route limits are explicit
in `native-controls.json`. The first tuple/list JSON comparison in the new
focused test failed and was corrected to canonical bytes. A binary tar copy
was removed from the proposed packet; the text-only bundle retains necessary
raw evidence without compiled products or captured artifact bytes.

Final checks: nine focused tests pass normally and under `-O` (exit0 each),
including the retained-stream/source-pin audit, strict bundle member allowlist,
frozen expected/input regeneration and actual-output corruption controls. The
static verifier passes normally and under `-O`; all13 packet manifest entries
pass (exit0). `make doctor`, `make verify`, `make catalogue-check` and
`make reproduce` exit0. Three target signatures, 38 imported files and all
seven source pins verify. Current compiler-read sources and fixture bytes
still match the accepted compiled receipt. Logs are
`/tmp/inline-carrier-final-checks/` and `/tmp/inline-carrier-focused-final.log`.

Initial verification exited2 while the fresh reference checkout still held
its LFS pointer. After authenticated materialization, it exited2 on that new
worktree's stale index status despite an identical normalized Git blob. Its
index was rebuilt from the same HEAD tree without changing content or pins;
standard invocation-only LFS filters then verify cleanly. Initial reproduction
also failed during this input setup. Final checks above pass; no gate was
weakened or persistent filter setting changed.

The approved compiler distribution has no rustfmt or cargo-clippy installed,
so those tools were not run or installed. The coordinator reports a failed
separate repository-wide baseline; no new full-suite run or passing suite on
this head is claimed. The older captured-instruction alias evaluator was not
run in this follow-on.
Long cache/ownership/allocation/display, native fault/unwind paths and whole
foundation reconstruction remain open.

## Current-source requalification for the key-hash extension

The original receipt/source snapshot remains preserved at published commit
`743257a699da958290d18dd89825c7a1804f58b8`, with exact source and snapshot pins
in `historical.json`; the ignored original output/snapshot is also unchanged.
Those historical observations above are not relabeled as this source build.

The new key-hash function changes whole-file source pins. The inline qualifier
was therefore rerun on the actual changed source, independently of the new
[48-case key-hash proof](../RE-001-key-hash-rust-94/README.md):

- Qualifier: `python3 -I -B research/work-items/RE-001-inline-carrier-rust-94/verify.py --qualify work/inline-carrier-key-hash-requalified`, exit 0.
- Fresh snapshot SHA-256: `24305d2e1c2707893040d3a95166d5dd9781b769209ed1a27f42b8904c60bd48`.
- Current `comparison.json` SHA-256: `80cfc156737cb03c65d3b92b447eff60b64e3968ec67fd9d7c03d91403a3c355`.
- All 15 builds/30 compiler invocations exit 0 with no diagnostics. Original
  156 native rows, two API-only refusals and all six source controls have the
  same comparison outcomes and raw output bytes. Repeated own opt3 products
  remain byte-equal; no target-code identity is claimed.
- Current raw text bundle: 156 inert members, decoded payload 7,984 bytes,
  SHA-256 `0404aa813f06bc287a6ffb0c486c0a67ff8564a43fac3f1e6c0847dd16bc4acb`.
  Compiled products and the private full archive are excluded.
- Locked/offline component builds and tests pass in debug/release. Each profile
  now runs five tests: the original four plus the separate key-hash fixture.
  `component-builds.json` retains actual commands/output and all current pins.

Current-source focused tests pass 9/9 normally (2.240 s) and under `-O`
(1.755 s), exit 0 each. `make doctor`, standard invocation-local LFS-filter
`make verify`, `make catalogue-check`, and `make reproduce` all exit 0.
The new key-hash focused group separately passes 8/8 normally and under `-O`.
Both packets' static verifiers pass normally and under `-O`; current scoped
manifests pass 14/14 each, and `git diff --check` exits 0.
No full suite on this head is claimed; the coordinator's separate baseline
attempted 972 child files and failed 22 child files for environment fixture
reasons (make exit 2), not a result from this head.
