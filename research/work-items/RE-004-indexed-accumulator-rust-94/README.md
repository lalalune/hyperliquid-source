# Node #94 indexed accumulator in safe Rust

This RE-004 packet reconstructs the complete 44-byte leaf
`[0x514ac60, 0x514ac8c)` from
[`foundation-indexed-accumulator-94`](../foundation-indexed-accumulator-94/README.md).
It adds a safe, dependency-free `no_std`
[implementation](../../../src/node94-indexed-accumulator/lib.rs), a full admitted
memory/arithmetic proof and actual native qualification. Original evidence,
tools, tests, imports, pins, registries and component gates remain unchanged.

The prior packet left Rust unimplemented and incorrectly described the return
as the index. The observed LEA at `0x514ac7b` changes full RAX to the loaded base
plus eight times the sign-extended index. The two following memory ADDs leave
RAX intact. This implementation returns that numeric entry address and preserves
the default-13 path, unconditional snapshotted addend and ordered wrapping qword
updates. The old tests still pass; that does not validate their prose's return
claim. The new `return_index` native control exposes the discrepancy.

The [proof](PROOF.md) permits all aliases within one ordinary image and all
effective-address wrapping before checking actual byte spans. New failures are
atomic safe refusals; original fault/partial-write behavior is not reconstructed.
The two updated qwords are provably disjoint because their addresses differ by
112 modulo `2^64`. Input ranges may overlap either word, so read order matters.
No original pointer ABI, mapping at arbitrary numeric addresses, source type,
function purpose, compiler provenance or compiled-byte identity is asserted.

## Static evidence and frozen oracle

The target is node #94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Fresh GNU, LLVM and Capstone decodes agree on all 12 instructions. The exact
FDE/CIE, neighboring boundaries, one leading and four following INT3 bytes,
internal branch/return closure and all 80,300 RELA records are checked. The
whole-text E8/E9 candidate scans and entry-naming relocation scan are empty.
No caller is invented from that absence; indirect references remain unknown.
All 16 structural corruption controls fail below the whole-file identity check.
`disassembly.json` retains actual commands, options and tool versions/hashes.

Before the Rust directory existed, `oracle.py` froze 3,120 complete input images
and independent expected records. It uses unbounded signed integer arithmetic
and an immutable final-byte overlay, not Rust execution or a captured-instruction
interpreter. `frozen.json` binds the target, static evidence, oracle source and
both streams. Of these cases, 2,986 succeed and 134 exercise all seven new refusal
categories. Local freeze chronology is not an external timestamp attestation.

`coverage.json`, reproduced by `audit_coverage.py`, reports 1,103 default-index
and 786 negative-index successes, including 106 minimum-i32 and 166 maximum-i32
cases. There are 571 wrapped entry calculations, 288 wrapped output-address
calculations and one wrapped index-field address; the actual accessed bytes
remain inside the admitted images. Every partial/exact eight-byte addend overlap
displacement `-7..7` is covered for each output word. Selector-pointer, index-field
and base-slot aliases, both arithmetic overflows, exact endpoints and missing
spans are also present. The 512-byte backing size is a harness choice, not a
library cap.

## Actual native results

The exact installed rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`, compiled the
new library and input-only client for `aarch64-apple-darwin` at opt-level 0 and 3.
Both profiles matched all 3,120 frozen records and passed three unit tests.
Overflow checks were on. Rebuilding each profile's library and client produced
four raw-byte identical artifacts, without normalization.

Fifteen wrong implementations were actually compiled and run in each profile.
Counts below are identical for both profiles; detailed admitted-value, admission,
return, memory and refusal-atomicity counts and first witnesses are retained.

| Mutation | Mismatches | Admitted value mismatches |
| --- | ---: | ---: |
| Return index instead of entry address | 2,974 | 2,974 |
| Default index zero | 1,111 | 455 |
| Zero-extend the index | 786 | 0 |
| Stride four | 2,765 | 1,492 |
| Wrong counter displacement | 2,990 | 2,986 |
| Wrong sum displacement | 2,630 | 2,610 |
| Decrement counter | 2,986 | 2,986 |
| Subtract addend | 2,250 | 2,250 |
| Saturate counter | 2,330 | 2,330 |
| Narrow addend to u32 | 1,656 | 1,656 |
| Load addend after counter store | 72 | 64 |
| Store only four counter bytes | 2,386 | 2,386 |
| Check sum after counter store | 20 | 0 |
| Reject exact endpoint | 466 | 0 |
| Saturate index-field address | 1 | 0 |

The zero-extension, endpoint and address-saturation controls differ through safe
admission outcomes on these fixtures, not through an admitted value witness.
The late-admission control corrupts memory in 20 cases that should refuse
atomically. Return-value and delayed-addend controls have actual admitted-value
witnesses. Missing/changed output, partial input framing and oversized harness
records are rejected as well.

`native/calls.json` records every argv, status, stdin hash and stdout/stderr hash.
`native/results.json` contains build/source/tool identities and comparisons.
`native/raw-streams.json.gz` retains all raw streams losslessly, with duplicate
payloads stored once. `checks.json` records completed repository/focused checks;
the SHA256 manifest binds all new files and the unchanged legacy tool/test.

## Replay and limits

From the repository root with materialized pinned inputs:

```sh
python3 -B research/work-items/RE-004-indexed-accumulator-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-indexed-accumulator-rust-94/audit_coverage.py
python3 -O -B research/work-items/RE-004-indexed-accumulator-rust-94/verify_rust.py \
  --rustc "$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)" \
  --out work/indexed-accumulator-rust/replay
```

The actual recorded native qualification used normal Python with `-B`. Static
replay also passed under `-O`, changed hash seeds and time zones. The native
verifier requires a fresh output directory and the actual pinned compiler bytes;
freeze commands refuse to overwrite files or run after Rust source exists.

Local `make doctor`, `make verify`, `make catalogue-check`, `make reproduce`,
13 focused legacy tests, binary-backed legacy evidence replay and rustfmt passed.
No full-suite or hosted-CI success is claimed here. No captured binary or
instruction emulator ran; no unlicensed inferred implementation was read/copied.
This is independently authored OpenAI/Codex work; the exact model identifier was
unavailable. It advances one value component, not a whole foundation/node gate.
