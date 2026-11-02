# RE-004: full COMISD pointer-prefix gate in safe Rust

Target: node94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
This bounded RE-004/foundation contribution adds only
`src/node94-double-gate` and this evidence packet. Imported pins, component
coverage, acceptance gates and generated progress remain unchanged.

## Reconstructed behavior

The complete leaf `[0x5028a40,0x5028a5b)` contains six instructions/27 bytes.
It reads P from RSI+0xf38, reads a binary64 payload at P, compares it with
the exact positive 1.0 literal using COMISD, and writes SETAE into AL.
The new API projects **full numeric RAX**: `(P & !0xff) | gate`.
Only ordered payloads at least one set the gate; the pointer's upper
56 bits survive. The prior `foundation-double-gate-94` packet left Rust
unimplemented and warned that the low-byte rule did not imply full RAX.

The safe integer-only `no_std` implementation takes an explicit immutable
numeric memory image and three comparison-mode booleans. It preserves
wrapped field-address formation, complete overlapping qword reads and the
original read order. New refusals describe missing/overflowing image spans
and comparisons outside the ordinary normal-completion domain. COMISD,
unlike UCOMISD, signals invalid for both NaN classes. DAZ suppresses the
subnormal-input exception even with the denormal mask clear. The mode never
changes the host floating environment. [PROOF.md](PROOF.md) derives the
complete raw-bit partition and cites Intel's primary instruction/MXCSR manuals.

No handler behavior, machine faults, flags/MXCSR status, XMM state, native
ABI or original compiled-byte identity is claimed. The fixed literal must
remain readable and unchanged; runtime-patched constants, racing/volatile
memory and code/control effects are excluded. Numeric address metadata is
not a Rust pointer or an assertion of a real process mapping.

## Static closure

`verify_static.py` binds the full actual body, unique FDE/CIE, neighboring
FDE extents and separate padding. GNU, Apple LLVM and Capstone independently
agree on every instruction boundary and byte. The actual COMISD RIP
operand resolves to the complete eight-byte 1.0 literal at 0x20a730 in
read-only .rodata, with its PT_LOAD mapping. The entry's naming slot at
0x5759108 is raw zero and has one symbol-zero RELATIVE writer.

All 80,300 RELA records are scanned for naming, overlapping slot writers
and any partial write into the constant/code/padding. Full .text E8/E9
candidate scans find no direct reference; this does not establish a complete
indirect-reference census. There are no helper calls or unresolved imports.
All 28 structural corruption controls fail independently of the initial
whole-file digest check. The saved raw GNU/LLVM exports are evidence only.

## Independent expectations and executed qualification

`oracle.py` froze inputs and expectations before Rust existed. It interprets
memory through a numeric-address dictionary, compares an exact integer
significand/exponent value against one, and reconstructs the pointer prefix
using byte-bucket arithmetic. The Rust source instead uses a raw unsigned
bit interval and masks. Neither side invokes the other or captured code.

The 18,200 cases include a 12,288-case grid of all 2,048 exponents, both signs
and three fraction endpoints; further NaN/subnormal cases under all eight
modes; every pointer low byte; high/wrapped addresses; overlapping reads;
and exact image endpoints/refusals. Each build matches 16,772 admitted
returns and 1,428 new API refusals. Opt0/opt3 and repeated builds produce
72,800 exact outputs overall. There is no output masking or normalization.
This finite qualification complements the universal proof, not an exhaustive
memory-map test.

All 28 wrong implementations were actually compiled and run at both
optimization levels: 56 effective controls. Thirty runs have a wrong-value
witness on an admitted input; the other 26 detect admission/refusal errors.
Controls cover COMISD versus UCOMISD, masks/DAZ, NaN/infinity/zero classes,
threshold inclusion, full RAX, field/payload bytes and ranges. Three unit
tests per profile, malformed-input checks and changed/missing-output controls
also pass. Same-option repeated library/client artifacts are byte-identical
(four comparisons, no normalization). No qualification failure occurred.

The actual compiler is rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The recorded recipe pins aarch64-apple-darwin, edition 2021, denied warnings,
one codegen unit, overflow checks, explicit opt0/opt3 and `/usr/bin/cc`;
tool versions and hashes are retained. Python 3.14.3, Capstone 5.0.7,
GNU binutils 2.47.20260726 and Apple LLVM 17.0.0 supplied validation tools.
Only newly authored Rust ran natively. No captured binary or instruction
emulator executed; no inferred unlicensed implementation was read or copied.

`native-result.json` records source hashes, full first mismatch witnesses,
profiles and repeat identities; `native-commands.json` retains all 194 commands.
All 388 original stdout/stderr streams are losslessly retained in
`native-streams.json.gz` with content-addressed base64 payloads. The nine
repository-check commands have another 18 streams in `checks-streams.json.gz`.
Archive parameters are gzip level 1 and mtime 0. Every decompressed payload,
command stream reference and source binding was verified. The manifest binds
all packet files and source, excluding itself and ignored Python caches.

```sh
python3 -O -B research/work-items/RE-004-double-gate-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-double-gate-rust-94/verify_rust.py \
  --rustc /Users/shinjun/.rustup/toolchains/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/double-gate-replay
```

Use a new output directory. The compiler path may differ; its exact identity
is checked. `frozen.json` binds the uncompressed fixture bytes, oracle and
static evidence as they existed before source creation. The native client
receives inputs only, never the frozen expected stream.

## Repository checks and limits

`make doctor`, `make verify`, `make catalogue-check`, `make reproduce`, the
legacy `foundation_double_gate.py --check`, all ten
`tests.test_foundation_double_gate` tests and rustfmt checks pass. Exact
commands, exits and unmodified streams are retained in the checks records.

The separate shared baseline at the stated source base attempted 971 files /
15,462 reported tests / 69 skips. Its original `make test` exit 2 was solely
three Errno28 disk-full errors; all 20 affected tests passed isolated retries.
This is not a successful full-sweep rerun or a full suite on this head.
Skipped Linux qualification and hosted CI success remain unclaimed.

Fresh pre-implementation inventories covered 165 open PRs, zero open issues,
100 recent merged PRs and tracked source; no matching address/topic claim
was found. `overlap.json` records scope, inventory hashes and exclusions.
Attribution: OpenAI / Codex client; exact model identifier unavailable.
