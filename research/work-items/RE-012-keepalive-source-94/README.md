# RE-002 / RE-012: node94 keepalive source and caller policy

Both complete keepalive helpers stop at the first failing option, but their
actual callers treat the resulting error as best effort: after normal logging
returns they continue configuring the socket. This packet closes that
previously unrecorded boundary and compares licensed public socket2 sources.
It does not claim a reconstructed networking runtime or a matching source build.

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Initial research/build base: `e5c9b6436876b2a4a39daef813171f9879317699`.
Integration base: `2c75904241b9165693d40dea8b0d0d340f8e22b3`. All addresses
are linked ELF VAs. The existing `transport-socket-calls-94` packet supplies the earlier
option-constant census; this contribution checks its own target bytes.

## New closure

- Complete helpers `[0x4ecd970,0x4ecda53)` and
  `[0x4ecda60,0x4ecdb43)`: 454 bytes / 120 instructions together. The
  unsigned seconds clamp, exact duration sentinel, full retry-tag equality,
  raw retry value, option order, exact -1 failure tests, errno packing and
  full RAX result are proved in [CONTRACT.md](CONTRACT.md).
- Complete caller contexts `[0x29aeb40,0x29af8ce)` and
  `[0x29c3300,0x29c4108)`: 7,062 bytes / 1,496 instructions. Their two
  direct calls are the whole-text direct-call census; neither helper has an
  address-taken RELATIVE slot. Context export is not whole-caller recovery.
- Both callers enable `SO_KEEPALIVE` before the helper. The server constructs
  all three optional fields and masks the retry tag to bit 0; the client
  constructs only a time option. Packed errors always have low bits 2, so
  the custom-error drop branch testing low bits 1 cannot run for these errors.
  The next-stage boundaries are `0x29af317` and `0x29c360c`.
- Twenty actual import/initial metadata/Location relocation records bind the
  two libc imports, the directly used socket2 Locations, and the tracing
  source paths. The server record names public Hyper 0.14.29; the client
  record names a private hyper-fork. Initial mutable tracing cells are not
  asserted to retain their ELF values throughout execution.

The full raw GNU and LLVM exports reproduce all 7,516 bytes, including caller
unwind/context bytes outside the semantic claim. Capstone decodes all 1,616
instructions. The helper protocol has no opaque private callee; the caller
logging, allocation, custom-error drop and async/runtime bodies remain external.
The continuation proof requires normal logging returns and preservation of the
borrowed stack error word; the opaque callback bodies are not independently
proved to satisfy that premise.

## Licensed source experiment

The unmodified official archives are checksum-pinned in `build_sources.py`:
socket2 0.4.10 with candidate libc 0.2.149, and socket2 0.5.7 with candidate
libc 0.2.150. Those are the Unix dependency versions declared by the respective
manifests, not a recovered original lockfile. Both use feature `all` for this
candidate experiment. Source licenses and complete source-file hash manifests
are retained. Public Hyper source is supporting attribution material, not the
private fork's recovered implementation.

The actual compiler is official Rust 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, hosted on macOS arm64, emitting
Linux x86-64 objects against a checksum-pinned official Linux standard-library
archive. The exact compiler executable hash is enforced by the recipe. The
only downloaded programs executed were the reviewed libc host configuration
helpers; with empty PATH they can run only the explicitly supplied rustc.
No emitted Linux object, captured binary, socket or emulator ran.

Both opt0 and opt3 builds completed for both versions. At each profile, the
repeat object and rlib were byte-identical: eight own artifact comparisons.
This is build reproducibility, not target equality.

The optimized public build inlines the internal helper into the public
`Socket::set_tcp_keepalive` symbol, whose 271 bytes also enable SO_KEEPALIVE.
That is not the target helper's semantic boundary and is not compared as though
it were. The retained `llvm-inline-threshold=0` and opt1 probes still did not
produce the internal symbol. No source annotations or machine bytes were
patched to force the target layout.

At opt0, each version emits the complete internal
`socket2::sys::set_tcp_keepalive` symbol: 418 bytes / 95 instructions. Its
unique source FDE, whole symbol, 14 relocations and all instruction bytes are
retained. The two source versions produce identical internal body bytes; that
does not identify which dependency generated either captured helper.

| Comparison | Denominator | Result |
| --- | --- | --- |
| Raw full-body equality | 4 alternative comparisons over 2 unique target windows | 0 equal |
| Normalized-only equality | same 4 comparisons; no normalization applied | 0 equal |
| Unmatched | same 4 comparisons | 4 unmatched, each 227 target bytes vs 418 source bytes |

No instruction was omitted, sliced to target length, padded or masked. Source
helper calls at opt0 remain explicit and are not claimed equivalent to target
inlining. Full generated-code identity is disproved for these declared
candidates, not for every possible source/build combination.

The global byte-window registry includes two `extent-mismatch` entries using
complete 418-byte socket2 0.4.10 opt0 candidates, one per target interval.
Both versions remain explicit `alternative_candidates` in each registry row,
with full source-body and object hashes plus comparison-record indices. The
identical 0.5.7 bodies add no denominator credit or version-to-target assignment.
The already-merged #1770 supplies unequal-extent registration. Its dependency
allowlist needed the single `socket2` entry to register this evidence honestly;
the actual prior collector rejected these rows with `Unknown dependency
attribution` (retained in `validation/registry-blocker.json`). A focused control
checks exclusion from aligned totals. Both rows remain
unmatched with no aligned-byte comparison, reconstructed-byte credit, component
gate change or first-party ownership claim.

## Reproduce

From repository root, with the pinned artifact materialized:

```sh
python3 -B research/work-items/RE-012-keepalive-source-94/verify.py
python3 -B -m unittest tests.test_keepalive_source94 -v
python3 -B tools/keepalive_source94.py \
  --target artifacts/node/94/hl-node --out work/keepalive-static-fresh \
  --objdump /opt/homebrew/opt/binutils/bin/objdump --llvm-objdump /usr/bin/objdump
```

The first command authenticates the manifest, target, complete source objects,
source FDEs/relocations, both raw disassembler byte covers and all archived
entries; it does not run a compiler. To rebuild, supply the five official
archives listed in `build_sources.py` (URLs/hashes in the source records), the
exact observed Rust executable, and a fresh output directory:

```sh
python3 -B research/work-items/RE-012-keepalive-source-94/build_sources.py \
  --input-dir /path/to/archive-cache --out work/keepalive-build-fresh \
  --rustc /path/to/observed/rustc
python3 -B research/work-items/RE-012-keepalive-source-94/compare_sources.py \
  --target artifacts/node/94/hl-node --build work/keepalive-build-fresh \
  --out work/keepalive-comparison-fresh
```

The recipe downloads nothing, requires complete authenticated archives, verifies
unmodified sources, records every command/stream, and rejects an unexpected
compiler. `protocol_relation.py` is only a finite mathematical counterexample
aid: it is neither a production socket shim nor native differential evidence.
There is no new independently authored Rust implementation claim.

## Observed validation and limits

On the initial research base, seven new focused tests passed in 42.491 s. They
include 60 static integrity checks: 31 code changes, four FDE extent changes, four source-path changes,
20 relocation changes and one whole-image truncation. These run below the
whole-image digest gate where applicable; the source-path checks compare the
regenerated scoped record, not just its file hash. Literal event expectations
also cover the sentinel, high-bit clamp, exact tag, every first-failure position,
raw -2 returns, and caller continuation instead of close/return-on-error.

Sixty-two existing socket-call, accept-context and FDE tests passed in 52.838 s,
without skips. `make doctor`, `make verify`, `make catalogue-check` and
`make reproduce` passed locally. The packet verifier additionally rejects six
actual ELF mutations (three classes in each candidate object) and replays the
complete comparison. The separate comparison records four byte-comparator
controls. These are not compiled wrong Rust implementations or target runs.

On the integration base, the qualified focused run passed 99 tests in 93.838 s:
eight keepalive tests, 29 byte-progress tests and 62 existing socket/accept/FDE
tests, without skips. This includes six registry-corruption controls in addition
to the 60 static controls. `make doctor verify catalogue-check reproduce`
passed in 112.462 s; the new packet-manifest gate checked 1,176 manifests and
19,097 entries, reporting 48 grandfathered historical missing rows. Those rows
are not credited as newly verified evidence. `make catalogue` regenerated only
the two unmatched rows; all existing aligned totals remained unchanged.

After rebasing, an initial combined test invocation ran 70 passing tests but
failed to import the existing byte-progress module because `tests` was absent
from the import path. Its complete output remains in `validation/`; the
qualified retry sets `PYTHONPATH=tests`. No source changed for that retry.
The three failed live GitHub search attempts also remain recorded; new-main
exact-address search found only the earlier socket-call census. The earlier
live search was empty, but a publication-time remote recheck remains necessary.

The first static exporter incorrectly interpreted FDE/CIE VAs as offsets into
`.eh_frame`; it stopped at frame-bounds validation. The exact failed script and
traceback are retained in `initial/`, followed by the corrected successful
records. No target or public source changed to repair that failure. Successful
builds that lacked the internal optimized symbol remain in the archived probe
history, not relabeled as source matches.

Raw evidence is a deterministic level-1 gzip JSON archive with exact per-entry
lengths, SHA-256 values and base64 contents. `archive-audit.json` records its
hash and successful lossless replay. No full repository suite, hosted CI,
Linux execution, source-built node, original dependency lock, live network
compatibility or complete caller behavior is claimed. The coordinating agent
owns any broader baseline reporting. Attribution: OpenAI / gpt-6-astra /
Codex 0.166.0, as provided by the coordinating session.
