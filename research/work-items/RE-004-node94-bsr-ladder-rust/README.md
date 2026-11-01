# RE-004: node94 BSR ladder in safe Rust

This adds an independently authored, dependency-free `no_std` Rust numeric
projection of one complete 88-byte function previously bound by the
[static BSR ladder packet](../foundation-bsr-clamp-ladder-94/README.md).
The gap addressed is the absence of executable Rust for that established
relation, including unsigned wrap, ordered bounds and the undefined-input
boundary. No component gate or byte-window credit is requested.

- Component/task: foundation / bounded RE-004 arithmetic reconstruction.
- Target: Linux x86-64 node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Repository base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Window: ELF VA `[0x556e980, 0x556e9d8)`, file offset `0x556d980`;
  body SHA-256 `5414e6009ee48d94319af3e60af05eec0ec123c3b2d8e8c74992e64df4e40fba`.
- Implementation: [lib.rs](../../../src/node94-bsr-ladder/lib.rs), with
  [input-only client](../../../src/node94-bsr-ladder/input_only_driver.rs).
- Source/reference use: only repository-authored static evidence and
  authenticated artifact bytes; no can1357 implementation was read or copied.

## Static evidence and derivation

`oracle.admit()` rechecks the full artifact digest, complete body, actual
CIE/FDE bytes and existing static predicates. It additionally decodes the
selected FDE's signed PC-relative start and 88-byte extent from the current
artifact. The FDE is at `.eh_frame+0x2d110c`, file offset `0xfb2624`, with
CIE offset zero and `zR` / `0x1b` encoding. The terminating `ret` is at
`0x556e9d7`. Eight padding bytes follow; they are outside the implementation.
The reused checker also retains its five old Python relation sanity cases;
they do not generate the new frozen expectations or compare the new Rust.

The fresh GNU disassembly is retained under label `target-disassembly`,
stream `stdout`, in `observed/raw-streams.json.gz`; the fresh selected CIE/FDE export
is [target.frames.txt](observed/target.frames.txt). GNU's nearest-symbol
annotation is not a source attribution. The artifact has not been executed.

Let `v`, `s`, `t`, `c` denote the low 32 bits of the initial `RDI`, `RSI`,
`RDX`, `RCX`. These labels give register order, not application meanings.

| Original ELF VA | Observation | Numeric consequence on admitted inputs |
| --- | --- | --- |
| `0x556e984..0x556e98e` | Preserve `EDI` in `EAX`, third input in `EDI`, low32(`RSI-1`) in `EDX`, fourth in `R8D` | All subsequent numeric operands are 32-bit |
| `0x556e98e`, `0x556e996`, `0x556e999` | Three `BSR` instructions on `s-1`, `t`, `s` | Domain is `s >= 2` and `t >= 1` |
| `0x556e991..0x556e9a7` | Load 31; XOR first BSR result with 31; subtract fourth and XOR result | `hi = (BSR(s-1) - c) mod 2^32` |
| `0x556e9a2..0x556e9af` | Increment BSR(s), add 2 to BSR(t), unsigned `cmova` | `lo = min(BSR(s)+1, BSR(t)+2)` |
| `0x556e9af..0x556e9b9` | Test original `v`; `cmove` 11 | `v0 = 11` if `v == 0`, otherwise `v` |
| `0x556e9b9..0x556e9d8` | Unsigned `cmova`, `cmovb`, `cmova`, `cmovb`; return | `max(min(max(min(v0, hi), lo), 12), 5)` |

For a nonzero 32-bit operand, `BSR` is in `0..31`; hence `31 XOR BSR`
equals `31 - BSR`. The two original 32-bit subtractions therefore reduce
to the stated modulo subtraction. Rust uses `wrapping_sub`, and every
comparison remains unsigned. The source preserves the min/max order rather
than assuming `lo <= hi`.

The original has no guards for zero BSR operands. The safe API returns
`None` for `s in {0, 1}` or `t == 0`. That is an explicit domain exclusion,
not an assertion that the target returns an error, zero, or any other value.
All operations in `Some` are defined Rust; BSR is expressed by
`31 - leading_zeros()` only after admitting nonzero inputs.

The body contains no calls, data loads, stores or relocatable references.
The prior checker's lack of direct `e8` byte-pattern callers remains a
limited scan, not complete caller/indirect-call closure. Original function
name, origin, calling convention beyond the observed register relation,
argument meanings and constants' purpose remain unknown. The sibling
`0x556e9e0` is excluded; only the old checker retains its existing boundary
check. No new implementation or semantic claim covers that sibling.

## Frozen mathematical expectations

[oracle.py](oracle.py) was run with `--freeze` before `lib.rs` existed. The
[freeze record](frozen/ORACLE-FREEZE.json) binds its source, the target/body/
FDE evidence, input-only TSV and separate expected output with SHA-256.
The validator checks these hashes and regenerates both fixture streams
without rewriting them. The originally frozen streams are gzip-archived
without changing their decompressed bytes or freeze hashes. Only the
input TSV is materialized under ignored `work/` for the client.

Review after Rust existed replaced one admission `assert` with an explicit
`ValueError` check, so optimized Python cannot remove the FDE assertion.
The exact pre-Rust oracle is preserved in
`frozen/oracle-before-hardening.py.txt` under its original hash. The freeze
record explicitly records the current source hash as a post-freeze
amendment; it does not claim that this revised source preceded Rust.
The oracle equations, corpus and frozen payloads did not change. The final
validator was run with `python3 -O` and still verified all hash/boundary checks.

The oracle uses power-of-two threshold lookup with `bisect_right`, not
Rust's `leading_zeros`. It does not execute the ordered min/max chain.
For each integer threshold `q` in `6..=12`, the inner result reaches `q`
exactly when `lo >= q` OR (`v0 >= q` AND `hi >= q`). The oracle computes
`lo >= q` by the conjunction of its two bit-rank bounds. The returned
value is 5 plus the count of attained thresholds. This follows directly
from the observed order and outer 5/12 bounds. It is a static mathematical
oracle, not original-code execution or an instruction emulator.

There are 35,540 distinct synthetic tuples: 31,374 admitted and 4,166
excluded. They cover both BSR input families at every representable power
of two and adjacent values, default/nondefault values, all output levels
5 through 12, wrapped subtraction, inverted inner bounds, `u32::MAX`, and
a fixed-seed mixed-magnitude sample. Coverage counts and witness indices
are in the freeze record. The full four-u32 input domain is not enumerated.

Two especially observable controls are `(7,32,32,0)` giving 6 versus 5
after reversing the inner operations, and `(8,65536,65536,0)` giving 12
versus 17 after moving the outer cap before the inner maximum. The old
packet's `(7,8,8,0)` example is masked by the final lower bound if the
inner operations are merely reversed; it is not used as proof of detection.
The zero-default witness `(0,4096,1,0)` produces 11, versus 5 without it.

## Build and observed results

Only newly built Rust runs, natively on `aarch64-apple-darwin`, using
rustc **1.94.1**, commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`,
LLVM 21.1.8, Python 3.14.3 and GNU objdump 2.47.20260726. The compiler's
standard/core libraries are its installed pinned toolchain components.
The library is built directly as an rlib, with no Cargo manifest, dependency
resolution, build scripts, third-party crates or root workspace. The
standard-library client gets only that input-only TSV, never expectations.

Both library and client use edition 2021, `-Dwarnings`, `panic=abort`,
`overflow-checks=yes`, `debuginfo=0`, one codegen unit, and a checkout-path
remap. Optimization levels 0 and 3 each have two independent compile/run
invocations. At each level the repeat rlib, executable and complete output
hashes are identical. All four runs match all 35,540 frozen expectations:
142,160 comparisons and zero mismatches. No original ABI layout or
x86-64 rebuilt-byte equality is inferred from these host results.

Eight altered libraries were actually compiled at opt3 and linked to the
same input-only client. The same frozen outputs rejected every variant:

| Deliberate wrong variant | Mismatching tuples / 35,540 |
| --- | ---: |
| Reverse inner min/max | 8,034 |
| Saturate upper subtraction | 8,371 |
| Compare upper bound as signed i32 | 6,524 |
| Default zero to zero instead of 11 | 2,380 |
| Use maximum for the lower bound | 17,423 |
| Omit the second-input predecessor | 1,103 |
| Move outer 12 cap before inner maximum | 6,747 |
| Invent `Some(5)` for excluded BSR inputs | 4,166 |

A separate one-row expectation corruption produced exactly one mismatch
against the real opt3 output; the frozen file was not modified. Actual
first mismatches, source changes, hashes and tool identities are retained
in [results.json](observed/results.json). Exact command arguments and exit
codes are in [commands.json](observed/commands.json). All build and native
stdout/stderr streams, including empty streams, are losslessly retained as
base64 in one deterministic `observed/raw-streams.json.gz` archive. Every
stream has its command label, stream name and SHA-256, checked against
`commands.json`; the raw bytes are unchanged. Only command paths are
rewritten from the checkout root to `/repo`.

The existing focused `tests.test_foundation_bsr_clamp_ladder` suite passed
all 12 tests. This worker did not run a second full repository sweep or
claim hosted CI success. Local `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce` passed. The first doctor
invocation selected Apple objdump; selecting installed GNU binutils on PATH
resolved it. The first verify invocation authenticated the artifacts but
rejected the materialized reference LFS file's Git status; the parent
restored its LFS filter/cache state without changing pinned content, then
verify passed. Initial and final check logs are retained in
`observed/repository-checks.json.gz`, with home/checkout paths redacted.
These checks are separate from the parent worker's full-suite run. No imports, pins,
progress records, old packets or generated catalogues are modified.
The read-only live PR/issue inventory was checked twice, with 33 open PRs
and zero open issues at the final check. Address/BSR/ladder searches found
no overlapping work; titles and status fields are retained in
[overlap-check.json](observed/overlap-check.json). Local source contained
no implementation of this relation. No claim, issue or external message
was created by this worker.

## Reproduce

From the repository root with the authenticated artifact materialized:

```sh
python3 tools/foundation_bsr_clamp_ladder.py \
  --check research/work-items/foundation-bsr-clamp-ladder-94/evidence.json
python3 -m unittest tests.test_foundation_bsr_clamp_ladder
python3 research/work-items/RE-004-node94-bsr-ladder-rust/validate.py
```

The validator defaults to `/opt/homebrew/opt/rustup/bin/rustc +1.94.1`
and `/opt/homebrew/opt/binutils/bin/objdump`. Override executable paths
with `--rustc` / `--objdump`; the exact rustc commit is still enforced.
Default output and compiled objects go under ignored
`work/node94-bsr-ladder/` (about 5.5 MiB for this run). The retained run
used `--output research/work-items/RE-004-node94-bsr-ladder-rust/observed`.
Its final invocation used `python3 -O` for the admission-hardening check.
Do not rerun `--freeze` after source exists; its guard prevents replacing
the original pre-Rust expectations.

## Remaining scope

The numeric projection is partial reconstruction of one foundation leaf.
Application identity, original ABI integration, original execution
comparison, target x86-64 code identity and full-component helper/data/
relocation closure are unmeasured. There are no normalization masks or
registered matched windows. Gates stay false. Live networking, chain
actions, keys, captured-code execution and the neighboring function were
outside this work. A future bounded question is which real callers admit
the defined BSR input domain and how they interpret the returned 5..12.
