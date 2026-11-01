# RE-004: node94 container pop/retreat Rust reconstruction

This packet adds one independently authored safe Rust component for the
complete leaf `[0x5178be0,0x5178c37)`. It resolves the prior foundation
packet's explicit missing Rust implementation and alias-sensitive memory
transition: the top-slot write precedes the popped qword load, so a
preloaded popped value is incorrect when the regions overlap. The API
returns full numeric RAX and reproduces the final byte image on admitted
normal-return inputs. This is a bounded RE-004 result; no project-wide
completion gate changes.

Target node94: 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Source: [`src/node94-container-pop`](../../../src/node94-container-pop).
Full semantics, proof, caller boundary and limits: [PROOF.md](PROOF.md).
The old `foundation-container-pop-helper-94` evidence, tool and tests are
unchanged. No inferred unlicensed implementation was copied or executed.

The library is `no_std`, forbids unsafe code, allocates nothing and has no
dependencies. One mutable image supports partial aliases at byte offsets.
The full-u64 contract uses wrapping addresses and arithmetic. Every
required slice range is checked before mutation; errors are a new atomic
refusal policy, not an emulation of the original fault path. Ordinary
stable memory, valid original accesses, and no code/control-state alias
are premises. Numeric image addresses are an explicit adapter, not host
pointers. No original library identity or business purpose is claimed.

## Evidence and reproduction

`disassembly.json` retains exact GNU/LLVM invocations, versions, tool
hashes and export hashes. `window.*.txt` covers all 87 bytes and 22
instructions; `caller.*.txt` covers all 1,261 bytes and 283 instructions
of the unique observed direct caller. `static.json` retains raw body,
FDE/CIE and adjacent padding records, full text direct-target census,
80,300 checked RELA records, and 21 effective corruption controls. The
leaf has no helper calls or external constant-data dependencies.

```sh
python3 -B research/work-items/RE-004-container-pop-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-container-pop-rust-94/verify_static.py
python3 -B research/work-items/RE-004-container-pop-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/container-pop-rust/fresh-replay
```

Use a fresh native output path. The actual executable is pinned by
SHA-256 `b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`;
rustc 1.94.1 commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`,
LLVM 21.1.8, host/target `aarch64-apple-darwin`. This is the tested
compiler/host recipe, not a recovered Linux target toolchain. Every exact
rustc/linker argument and linker identity appears in `native-calls.json`
and `native-results.json`. The build uses explicit `-Dwarnings`,
`-Coverflow-checks=on`, one codegen unit and opt-level 0 or 3.

`oracle.py` formulates an immutable per-byte overlay relation with
unbounded integer arithmetic. `frozen.json` binds its hash, the target,
the static record and fixed streams, and records that the Rust source
directory did not yet exist. `inputs.bin.gz` and `expected.bin.gz` use
deterministic gzip. The 274-byte input records contain only base, object,
admitted image length and 256 synthetic image bytes. The 265-byte output
records contain error tag, numeric result and full resulting image.
The separate new native client contains no expected answers. Freeze is
an authoring step, not a replay operation; do not regenerate expectations
from native results.

## Completed local checks

Both native profiles matched all 1,531 frozen rows: 824 admitted pops,
568 admitted retreats, and 139 refusals. Every error variant is covered.
Each profile passed three additional unit tests and rejected partial
records and oversized image lengths. Rebuilding both profiles produced
byte-identical rlibs and client executables (four comparisons, no output
or artifact normalization).

Sixteen actually compiled incorrect implementations were detected in
each profile (32 runs): inverted/low32 equality, retreat distance,
counter decrement and saturation, top distance, preload/late popped
load, pair increment, return adjustment, swapped pair, narrowed popped
value, unchanged top, late range admission, strict endpoint and
saturating field address. The preload and late-load variants differ on
88 and 89 admitted rows respectively. Late admission changes memory on
27 refused rows. `native-results.json` records counts and concrete first
witnesses for every control; these are observed native mismatches, not
handwritten assumed outcomes.

Static replay passed under regular Python and `-O`, different hash seeds
and UTC/Kiritimati time zones, with identical retained output. Pinned
rustfmt check passed. Local `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce` passed. The unchanged focused
`test_foundation_container_pop_helper.py` suite passed all eight tests,
and its legacy evidence checker reproduced exactly. `checks.json`
records these nine commands, environments, exit codes and stream hashes.
Doctor still reports `exact_rebuild_ready: false`; that existing gap is
not altered. No duplicate full suite, hosted CI or original target
execution is claimed here.

`native-raw-streams.json.gz` losslessly retains stdout/stderr for all
120 native recipe commands (240 named streams, 23 deduplicated payloads).
`checks-raw-streams.json.gz` retains all local-check streams. Both archives
map stream labels to SHA-256 and those hashes to base64 payloads; every
payload was decompressed and checked against the original logs. Native
binary stdout is unmodified. Call metadata substitutes `<repo>`,
`<rustc>` or `<home>` for local path prefixes where applicable. Raw tool
streams remain unchanged. Build outputs live only under ignored `work/`
and can be recreated from these recipes.

`overlap.json` records final read-only checks of 114 open PRs, zero open
issues, 100 recently merged PRs and current `origin/main` source. No
matching address or container-pop implementation was found. The scope
was reserved with the coordinating contributor before source authoring.

The finite tests support the full-domain argument in PROOF.md. They do
not establish original compiled-byte identity, original ABI equivalence,
complete indirect callers, whole-node behavior, fault/exception state or
cross-platform native reproducibility. Existing acceptance gates and
submodule pins remain unchanged.
