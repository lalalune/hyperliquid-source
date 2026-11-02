# RE-004: self-guarded field chain with complete RAX/RDX

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Only `src/node94-self-guarded-chain` and this packet are added. Imported pins,
progress, catalogue and full-scope acceptance gates remain unchanged.

## Reconstructed relation

The complete leaf `[0x5172e50,0x5172e77)` contains 39 bytes/10 instructions.
It reads P at RDI+8, compares all 64 bits of P with the qword at P, and returns
all ones in both RAX and RDX when equal. Otherwise it reads Q at P+8, R at
Q+16 and V at R+0xcb8; both full registers return V. The source is independently
authored safe `no_std` Rust. The predecessor `foundation-two-hop-field-load-94`
left independent Rust implementation/build qualification unimplemented.

This is a self comparison, not a null check. Numeric zero can be a represented
pointer; the guard qword is still required. Only the unequal branch requires
the three later reads. Each address addition wraps modulo64. All input spans
may overlap because the original and the new API are read-only. A legitimate
all-ones chain result remains successful. [PROOF.md](PROOF.md) establishes
both paths for all u64 words and the exact normal-memory domain.

The new image API requires a nonwrapping numeric interval and every complete
reached eight-byte span. `None` is a new safe refusal, distinct from the valid
all-ones return. The library has no fixture-size cap. Numeric addresses never
become Rust pointers. Correspondence assumes stable ordinary memory and
normal instruction/read/return control. Native ABI, flags, faults, MMIO,
races, control-data aliases, handlers and original compiled-byte identity
remain unclaimed. No source type or sentinel meaning is inferred.

## Complete static and caller context

The full body, unique FDE/CIE, neighboring FDE extents and separate seven/nine
INT3 padding bytes are authenticated. GNU, Apple LLVM and Capstone agree on
all bytes and instruction boundaries without normalization. The forward JE
and sole RET are closed; there is no helper call or RIP-relative data operand.

One E8 candidate at 0x51523bc is boundary-confirmed within the complete caller
`[0x5152280,0x51524a9)` (553 bytes/130 instructions). No E9 candidate exists.
The caller's whole body/FDE/CIE is retained as call-boundary context; its
algorithm, unrelated helpers and LSDA/personality behavior are not reconstructed.
All 80,300 RELA records are scanned, with no leaf-naming record or overlapping
writer into protected body/padding/caller bytes. These scans do not establish
complete indirect reachability. All 32 structural corruption controls reject
independently of the initial whole-artifact hash check.

## Independent freeze and executed qualification

All 7,492 fixtures, expectations, the static record and oracle were frozen
before Rust existed. The oracle uses an immutable numeric-address map,
unbounded byte-weight arithmetic and a difference residue to classify the
guard. Rust uses checked slice reads, full u64 equality and wrapping additions.
The oracle neither imports Rust nor steps captured instructions. The native
client receives inputs only, never expected outputs or target code.

Per build, 1,302 self-path results and 3,921 chain results are admitted;
2,269 inputs qualify new API refusals. Coverage includes all result bits,
high/zero/all-ones values, partial/exact aliases, wrapped addresses and exact
span boundaries. There are 128 self successes without a next span, 44 valid
zero-pointer chains and 1,021 unequal guards that agree in their low32 bits.
Two overflowing-image descriptions keep reached reads valid to isolate the
global image rule. No post-freeze fixture additions were needed.

Opt0/opt3 and repeated builds produce 29,968 exact status/RAX/RDX records:
20,892 admitted results and 9,076 refusals. All 26 wrong implementations were
actually compiled and run at both levels, producing 52 effective controls.
Twenty-four runs have admitted-value witnesses; 28 detect admission errors.
Controls cover guard width/polarity/null substitution, default width, eager
tail reads, incorrect field offsets, saturating/narrowed addresses, byte order,
full RAX/RDX, sentinel/refusal confusion and image/span boundaries. Three unit
tests per profile, malformed-input and changed/missing-output checks pass.
Four same-option repeated library/client artifacts are byte-identical with
no normalization. No native or control-preflight failure occurred.

The installed compiler is rustc1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The recipe binds aarch64-apple-darwin, edition2021, denied warnings, one codegen
unit, overflow checks, opt0/opt3 and `/usr/bin/cc`. Python3.14.3, Capstone5.0.7,
GNU2.47.20260726 and AppleLLVM17.0.0 supplied static/validation tools. Only new
Rust ran natively; captured execution/emulation and whole-node equivalence
are not claimed.

## Raw evidence and reproduction

All 180 native commands and 360 raw stdout/stderr streams are retained.
Each distinct stream is first checkpointed to a content-addressed gzip before
any assertion, with small call/index metadata updated incrementally. Final
consolidation writes one lossless JSON/base64 gzip archive. Unexpected runtime,
comparison or control failure also triggers consolidation before propagating.
Both checkpoints and final archive use level1/mtime0. This avoids repeatedly
compressing the growing collection while preserving failure evidence.

`native-streams.json.gz` is 456,698 bytes and retains every exact stream;
`native-result.json` records source/tool hashes, complete mismatch witnesses
and repeated-artifact identities. `mutant-preflight.json.gz` retains all
26 successful metadata builds and exact generated sources. The checks archive
adds 18 streams. `archive-audit.json` confirms all payload/command/source/freeze
bindings and that incremental checkpoints equal the final archived raw bytes.
The manifest binds packet/source files, excluding itself and Python caches.

```sh
python3 -O -B research/work-items/RE-004-self-guarded-chain-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-self-guarded-chain-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/self-guarded-chain-replay
```

Use a fresh output directory. The compiler path may differ but its exact binary
identity is checked. No new dependency or invented workspace/lockfile is needed.

## Repository checks and limits

Doctor, verify, catalogue-check, reproduce, the legacy foundation packet check,
all 14 focused predecessor/FDE/GNU-tool tests and rustfmt pass. Exact commands,
exits and original streams are retained in the checks records.

The separate shared baseline at the stated source base attempted 971 files /
15,462 reported tests / 69 skips. Original exit2 was solely three Errno28
disk-full errors; the 20 affected tests passed isolated retries. No successful
full-sweep rerun, full suite on this head, skipped Linux qualification or
hosted CI success is claimed.

Fresh pre-implementation checks covered 196 open PRs, zero open issues,
100 recent merged PRs and current tracked source without matching scope.
`overlap.json` records inventory hashes and reservations. Attribution:
OpenAI / Codex client; exact model identifier unavailable.
