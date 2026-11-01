# RE-004: node94 BSR shift-mask raw value in Rust

This adds independently authored, dependency-free `no_std` Rust for the
complete 66-byte helper already bound by the
[static shift-mask packet](../foundation-bsr-shift-mask-94/README.md).
It closes the implementation gap for this one numeric relation, including
the high-bit/zero wrapping cases and the final bit-index floor. No
component gate or target-byte matching credit is requested.

- Component/task: foundation / bounded RE-004 arithmetic reconstruction.
- Target: Linux x86-64 node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Function: ELF VA `[0x54b4390, 0x54b43d2)`, file offset `0x54b3390`;
  SHA-256 `b85a1e72bd3d84ce2bfb404662d562a60ac734147d4086a47bf9323cbc128fb1`.
- Rust: [lib.rs](../../../src/node94-bsr-shift-mask/lib.rs), with
  [input-only client](../../../src/node94-bsr-shift-mask/input_only_driver.rs).
- Authorship: new MIT source and fixtures, based on authenticated bytes and
  existing project-authored evidence. No can1357 implementation was consulted
  or copied into this reconstruction.

## Byte-derived relation

The complete body starts with a `lea`, has no `endbr64`, calls or conditional
branches, and ends with a single `ret` at `0x54b43d1`. The one input is
the initial u64 `RDI`. Other input registers are overwritten before use.
The body has no explicit data memory operands; the raw returned value is
written to `EAX`. No input quantity, field meaning or caller purpose is inferred.

| ELF VA | Observed relation |
| --- | --- |
| `0x54b4390..0x54b43a8` | Preserve input `n`, form `q = (2*n−1) mod 2^64`, load an all-ones mask, compute `k = BSR(q)` |
| `0x54b43a8..0x54b43ba` | Unsigned compare/select `max(k,7)`; form `z = (n−1) mod 2^64`; set `s = max(k,7)−3` |
| `0x54b43ba..0x54b43c6` | `SHL` the u64 all-ones mask by `s`; AND with `z`; logical `SHR` by `s`; retain low two bits with `AND EDI,3` |
| `0x54b43c6..0x54b43d2` | Unsigned compare/select `max(k,6)`; `LEA EAX,[RDI+4*RSI−23]`; return |

Thus the exact selected-mask relation is
`field = ((z & (u64::MAX << s)) >> s) & 3`, and the final u32 value is
`field + 4*max(k,6) − 23`. The final floor is 6, distinct from the shift
floor of 7. Omitting it gives the wrong result for rank below 6. The Rust
keeps the original all-ones mask and explicit wrapping input arithmetic.
Its final add/subtract operate on u32, matching the observed EAX width.

Every u64 input is defined: `q` is odd, so it cannot be zero. Consequently
`k` is in `0..=63`, `s` in `4..=60`, and hardware shift-count masking has
no effect. Both Rust shifts have a count strictly below 64. The two-bit
field is in `0..=3`, the final clamped rank is in `6..=63`, and the final
expression is in `1..=232`; there is no final arithmetic overflow on the
admitted domain. The source still uses explicit u32 wrapping operations.
No `Option`, error result or zero-input exclusion is appropriate here.

The original EAX write zero-extends the result to RAX. The safe API returns
the numeric u32 value; it does not establish the original function ABI,
name, crate, type or application role.

## Complete FDE and caller checks

The selected FDE is at `.eh_frame+0x2bf8c8`, has CIE offset zero with
`zR` / pcrel sdata4 encoding, and decodes to exactly the 66-byte extent.
Fourteen `int3` padding bytes follow, outside the function. The next FDE
starts at `0x54b43e0`; its semantics and implementation are excluded.
The old checker retains its existing next-boundary check without expanding
this contribution's scope.

Fresh static admission checks the full artifact digest, complete body,
CIE, selected/caller FDE records and padding. The direct call sites are:

| Call site | Caller FDE | Fresh linear decode |
| --- | --- | --- |
| `0x54c6268` | `[0x54c5620,0x54c7547)` | 7,975 bytes / 1,720 instructions |
| `0x54c85d5` | `[0x54c7550,0x54c8ca5)` | 5,973 bytes / 1,220 instructions |

Fresh Capstone decoding covers both entire caller bodies and confirms the
two calls as instruction starts with the expected relative target. Caller
body hashes, exact call bytes and FDE raw records are frozen. The existing
whole-`.text` direct-call pattern scan and zero naming-relocation check
also reproduce. The checker retains its six old numeric sanity cases, but
they do not generate the new expected outputs or compare the new Rust.

These are bounded linear checks, not a complete xref census or proof of
caller control flow. Caller argument meaning and runtime reachability
remain unknown. No wider BSR family is claimed.

Fresh GNU helper and both caller disassemblies are retained under labels
`target-disassembly`, `caller-1-disassembly` and `caller-2-disassembly` in
`observed/raw-streams.json.gz`. [target.frames.txt](observed/target.frames.txt)
contains the fresh selected CIE and three FDE exports. Nearest-symbol
annotations are not source attributions.

[verify_static.py](verify_static.py) additionally flips bytes in in-memory
copies after bypassing full-file digest admission for the negative controls.
Six independent structural checks reject changed body-mask bytes, FDE
extent, CIE encoding, padding and each caller's relative target. Results
are in [static-controls.json](observed/static-controls.json). Corrupted
bytes are parsed only; no captured instructions are executed or emulated.

## Independent pre-Rust oracle

[oracle.py](oracle.py) froze its source hash, target/structure facts and
input/output hashes before the new Rust source existed. Both fixture streams
are retained as deterministic gzip archives; their hashes cover the exact
decompressed bytes. The validator checks them and regenerates them without
rewriting the archives. All guards use explicit exceptions, including when
run with Python optimization.

The oracle does not double the input or evaluate bit-scan/shift operations.
It uses `H = 2^63`, residue `r = n mod H`, and integer intervals:

- `r == 0` corresponds to `q = 2^64−1`, hence `k = 63`.
- For `r > 0`, `k` is the smallest integer with `r <= 2^k`. For `k >= 1`,
  the interval `2^(k−1) < r <= 2^k` implies
  `2^k <= 2*r−1 < 2^(k+1)`; the `r = 1` case gives `k = 0`.
- Let `D = 16` for `k <= 7`, otherwise `D = 2^(k−3)`.
  The field is `((r−1) mod (4*D)) // D`.

The last expression follows because clearing low bits before shifting is
equivalent to integer division by `D`, then keeping two bits is reduction
modulo 4. Also `4*D <= 2^62` divides `H`, so reducing `n` modulo `H` first
preserves that field even when `n−1` wraps. This independently derives the
value's period `2^63` and handles zero without a special invented output.
The source's explicit mask is retained; removing its redundant low-bit
clear before the right shift would not be an effective value mutant.

The frozen corpus has 12,026 distinct u64 inputs, all admitted. It includes
every rank `0..63`, all field values, adjacent rank/field boundaries,
small values and their high-bit partners, wrap endpoints, and 4,096 seeded
residues together with their period partners. The observed range is 1..232.
The algebraic bounds cover the full domain; the test corpus does not
enumerate all `2^64` inputs. Coverage counts and witnesses are in
[ORACLE-FREEZE.json](frozen/ORACLE-FREEZE.json).

## Native builds and actual negative controls

Only newly authored Rust executes, on `aarch64-apple-darwin`. The compiler
is pinned rustc **1.94.1**, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8. Other tools are
Python 3.14.3, Capstone 5.0.7 and GNU objdump 2.47.20260726. The library
is built directly as an rlib without Cargo, third-party dependencies or
build scripts; core and the client's standard library come from that
installed toolchain. No recovered workspace or Linux build is implied.

Library/client builds use edition 2021, `-Dwarnings`, `panic=abort`,
`overflow-checks=yes`, `debuginfo=0`, one codegen unit and checkout-path
remapping. Opt0 and opt3 each have two compile/run invocations. Every
build matches all 12,026 rows: 48,104 comparisons and zero mismatches.
Within each optimization level, repeat library, executable and complete
output hashes are identical. The client only receives input values, never
expected outputs.

Nine altered libraries were compiled at opt3, linked to the same client
and tested against the same frozen expectations:

| Deliberate wrong variant | Mismatches / 12,026 |
| --- | ---: |
| Omit final rank floor of 6 | 64 |
| Widen doubled-minus-one to u128 | 6,012 |
| Use 7 as final rank floor | 128 |
| Use 6 as shift-selection floor | 96 |
| Subtract 2 rather than 3 for the shift | 9,030 |
| Keep only one field bit | 5,864 |
| Extract from n rather than n−1 | 464 |
| Saturate n−1 | 1 |
| Form doubled-plus-one | 116 |

The widened mutant keeps `n = 0` defined explicitly so every mutant run
completes and produces comparable values. At `n = 2^63+1`, it returns 233
instead of 1, exposing the omitted u64 wrap. The missing-final-floor
mutant returns 4294967273 instead of 1 at `n = 1`. Saturating the field
predecessor changes the zero input from 232 to 229. A separate one-row
expectation corruption gives exactly one mismatch against actual native
output, without changing the frozen archive.

[results.json](observed/results.json) records all counts, source/build
hashes and first mismatches. [commands.json](observed/commands.json)
records commands and exit codes. One deterministic `raw-streams.json.gz`
stores original stdout/stderr bytes losslessly as base64, with labels and
SHA-256 hashes, including empty streams. Only command paths are remapped
to `/repo`; raw streams are unchanged.

The existing focused shift-mask suite passed all 8 tests. Local
`make doctor verify catalogue-check reproduce` also passed with installed
GNU binutils first on PATH. Their combined stdout/stderr is retained in
`observed/repository-checks.json.gz`, with home/checkout paths redacted.
The validator ran under `python3 -O`; all 88 archived raw command streams
were separately decoded and hash-checked. No second full test sweep ran.

Live overlap checks found no address or shift-mask conflict: 47 open PRs
at selection and 49 at the final check, with zero open issues. Existing
BSR ladder/normalization PRs cover distinct functions. Final titles and
draft/review status are retained in [overlap-check.json](observed/overlap-check.json).
No claim, issue, PR or external message was created by this worker.

## Reproduce and remaining scope

From the repository root with pinned artifacts materialized:

```sh
python3 tools/foundation_bsr_shift_mask.py \
  --check research/work-items/foundation-bsr-shift-mask-94/evidence.json
python3 -m unittest tests.test_foundation_bsr_shift_mask -v
python3 -O research/work-items/RE-004-node94-bsr-shift-mask-rust/validate.py
```

The validator defaults to `/opt/homebrew/opt/rustup/bin/rustc +1.94.1`
and `/opt/homebrew/opt/binutils/bin/objdump`; executable paths can be
overridden with `--rustc` / `--objdump` while the exact compiler commit is
still checked. Native build products remain under ignored
`work/node94-bsr-shift-mask/`. The retained invocation used
`--output research/work-items/RE-004-node94-bsr-shift-mask-rust/observed`.
The `--freeze` guard refuses replacement after Rust exists.

This contribution does not establish original ABI integration, source
provenance, caller purpose, target x86-64 compiled-byte identity or full
foundation helper/data/relocation closure. No normalization masks, matched
byte windows, hosted CI success or full repository test completion are
claimed. Captured execution, instruction emulation, live node/chain actions,
unlicensed implementation copying and neighboring functions were excluded.
Prior evidence, imports, pins and progress gates remain unchanged. The
remaining bounded question is what values the two observed callers pass
and how they use the opaque u32 result.
