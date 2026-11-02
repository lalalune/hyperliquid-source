# Seed factory results

All execution below is independently authored Rust. No captured program,
emulator or captured-instruction evaluator ran. Logical pair semantics do not
establish runtime entropy/readiness, original TLS/Once/cache ABI or any gate.

## Exact pre-source freeze and native proof

- Native freeze: `2201df213104ca7b79a63049512a90692b22915c9c829e0db04c1419f56b2de0`.
- Rust projection plan: `d46958f9e908781cf15175a6d5abc9ed783c7ad74f6f1d60dd8be9e5d6133465`.
- Fixture: `bb9b28e67c7a32160c891e200f5296cf5dab45e61baaeaa28b90d76ec80b9695`.
- Input280B: `13ccd7eb23460664ff3f671a195a974fbb75388fa1b00973421ce2ac3391f196`.
- Expected357B: `a6596bb6114a70254d1390f83c77204bbd2bd66ae6f8ff89b37ff01837d9cbc5`.
- Two complete new FDEs197B/51 matched rows; credited Once540B; exact raw
  FDE/CIE/index, four relocations, caller/data/constant bytes and full exports.
- Seven full native frozen output/TLS envelopes and four operative static
  source-site controls pass. Branch control only classifies leaving the admitted
  path. E=b0 pointer and noncanonical flags are explicitly diagnostic.

## Qualified Rust and real component build

Official Rust 1.94.1, x86_64-unknown-linux-gnu, LLVM21.1.8, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`; rustc SHA-256
`ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`.
Source/expected byte closure is finite and explicit;68 selected compiler/std/
linker files do not supply whole-node compiler/linker/runtime provenance.

- Production library: `760f78188f1104f5b85aa6d14cee31ae6b7484cc97a84615200107e3ec0e7deb`.
- Immutable source/input snapshot: `3fbcd1420994218385d5a8a7550dce83f53888d7d0a0af983a1f5c1d3a26845d`.
- Actual receipt: `fc6f199241660dc5a06f971e64a7ccf1e0eddc4485af2d35b10962927280dbe7`.
-16 builds/32 actual compiler commands, all exit0/no diagnostics, opt0/3.
  Each baseline matches7/7 cases and all357 output bytes (336 numeric bytes).
  Nine project source/input pins and exact two-.rs compiler-read closure checked.
- Seven source mutants differ per profile: return-new7, omitINC7, increment-high7,
  memory32 INC3, decrement7, swapped return6, wrong-native-SIMD-source7.
- Four actual malformed framing controls per baseline exit1 with exact stderr
  and empty stdout. This is harness behavior, not native rejection behavior.
- Actual locked/offline Cargo debug/release tests pass6/6 per profile. The
  original alias/hash/feed/inline regressions remain; new test calls factory
  once, hashes twice with its returned pair and checks source does not advance
  per key. Existing real manifest/lockfile/dependencies are unchanged.
- Raw text132 members, compressed3502B, payload SHA-256
  `cbf7014a6d1efa40ae9378dcecf9b93bff576c1ba29a10ab2a0b4a143d3949fd`.
  Encoded payload has only inputs/expected/actual outputs, compiler logs,
  dep-info, recipes and snapshot hashes; no source, product or captured image.
- Minimum recorded qualifier post-compiler free381MiB, floor300MiB with16MiB
  pre-call transient allowance. Authored completed nonbaseline/opt0 products were
  removed after run/hash, baselineopt3 and all source/input/raw evidence retained.

## Honest historical versus current integration

Published a994e34e old source 8b1d5e79 and inline 80cfc156/key-hash 1100279a are
preserved in Git, separate historical indexes and private archival copies. The
factory source760f caused two existing focused current-whole-lib pin assertions
to fail, as intended. No numerical failure was found and no assertion is relaxed.

A first guarded fresh inline run completed opt0 then stopped BEFORE opt3 when
free330690560B was below the316MiB pre-call threshold. Its source/input/products/
raw logs/audit remain. The old runner had only RAM build receipts until the end;
no nonexistent receipt or missing framing observations were reconstructed.

Approved private wrapper11a2979367d087e29d7a2a24e8ed9830d248aa45e9ca1d6216bcd52e4e8f8c70
saved ACTUAL core qualifier per-build records atomically, tagged PARTIAL until
full core success. Fresh complete current-lib runs then passed unchanged corpora:

| Corpus | Builds | Current actual receipt |
| --- | ---: | --- |
| Inline156+2, six mutants, own opt3 repeat |15| `c727112a63adca748b3c075ca53125ec95e30979eb7c277fd19bc26c537ba61d` |
| Key-hash48 pairs, seven mutants |16| `a7261c5b77583d5ff9247b0ff36e595754851ba21304f53de817a3b3f3d84c3f` |

The unchanged tracked qualifiers pin actual source760f and all 7/8 respective
project source/input files,68 providers and exact two-.rs dependencies. Their
actual15/16 completed-build lists equal durable checkpoint lists. Every real
rustc pre-call had at least316MiB and post-call at least300MiB; measured minimum
post-call344/331MiB. Audits retain24/28 actual nonbaseline product cleanups;
ALL baseline products, source/input/logs/receipts and old stopped/historical
outputs remain. Guard/cleanup/checkpoint/source-code evidence is losslessly
retained as bounded text. No compiler reran solely to move evidence files.

## Final affected checks

Current-source Cargo6/profile and the four required read-only repository checks
(`make doctor`, invocation-local standard-filter `make verify`,
`make catalogue-check`, `make reproduce`) pass exit0 on unchanged760f source and
fixtures. Reproduce was serialized separately from orderbook. Doctor says
analysis ready/exact rebuild not ready. Three target signatures,38 imports and
seven pinned reference repositories verify; no input/pin is modified.

Affected focused tests pass8/8 for the new factory (2.113s),9/9 for current
inline (1.667s),8/8 for current key-hash (4.490s). New factory8/8 also passes
under Python-O (0.971s), and its verifier passes normal/-O. The old two
current-pin failures are fixed through real fresh qualification, not skipped
assertions. All three packet verifiers pass; affected focused groups pass under Python-O
also: inline9/9 (1.618s), key-hash8/8 (3.641s), factory8/8 (0.971s).
Scoped manifests pass seed20/20, inline15/15, key-hash15/15; diff --check exits0.
No compiler rerun solely for text packaging. No new full suite on this head is claimed.
The coordinator's separate baseline attempted972 child files and failed22 child
files for environment fixture reasons (make exit2), not this head's result.
Rustfmt/Clippy were unavailable and were not installed or claimed.

## Remaining scope

Initialization lifecycle is caller-owned; the API does not enforce once-only
usage. Flag 0 provider, slow FS:0 self-pointer relation, entropy/readiness,
Once concurrency, original alias/cache/TLS types and ABI, global lifetime,
allocator/copy/free, probing/equal-key behavior, fault/unwind/runtime validation,
original machine-code equivalence and all whole-component gates remain open.
