# RE-009: complete Ctx successful-wire profile for Node115

- Component: abci; task: RE-009.
- Target: Linux x86-64 hl-node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Public rule/parser baseline: main 05bc2de303c05525b71e7e257426e741bc66a390.
- Status: independently authored Rust for all thirteen fields in the declared successful-wire profile, with static target evidence. No component gate change.
- Before this work the repository had selected Ctx dispatch/height-decoder packets but no complete Ctx encoder crate. This addresses that reconstruction gap, not a reproduced production software defect.
- Prior RE-009 state-dispatch and binary-context packets are context, not newly reconstructed bytes. No compiled-code byte coverage is requested.

## Reproduce

From the repository root, use Python3 with Capstone 5.0.7 and the existing authenticated artifact:

    python3 -B research/work-items/RE-009-ctx-encoder-115/extract.py --target artifacts/node/115/hl-node --out work/ctx-contexts.json
    python3 -B research/work-items/RE-009-ctx-encoder-115/qualify.py --input-dir research/work-items/RE-009-ctx-encoder-115 --out work/ctx-qualification.json
    python3 -B -m unittest discover -s tests -p test_node115_context_encoder.py -v
    cargo test --offline --locked --manifest-path src/node115-context-encoder/Cargo.toml
    cargo build --release --offline --locked --manifest-path src/node115-context-encoder/Cargo.toml

Compare the newly extracted JSON with contexts.json; the regeneration test does this in memory. The actual provider version is recorded separately. GNU objdump 2.47 used -d -z --insn-width=16 with the full start/end VA of each selected FDE. gnu-disassembly.txt preserves its output, with only the operator artifact pathname replaced by <NODE115>. The comparison checks instruction addresses, byte partitions and all 10,326 bytes, not textual mnemonic spelling.

To regenerate the data witness with the pinned Windows rustc executable:

    python3 -B research/work-items/RE-009-ctx-encoder-115/compile-format-witness.py --rustc <RUSTC_1_95_GNULLVM> --out-dir work/ctx-format-witness

The formatter witness compiled seven separately authored format-only Rust functions to AMD64 COFF objects with rustc 1.95.0 (59807616e, LLVM 22.1.2), opt-level 2, debuginfo 0, emit=obj. Four positive descriptors and three sign/zero/width controls match or differ as expected. No witness code was executed. format-descriptor-witness.json preserves the exact specifications, compiler/object/source hashes, section coordinates and bytes. This compares static descriptor data only, not Linux/Windows ABI or compiler identity. Standard formatting interpretation: https://doc.rust-lang.org/std/fmt/.

Implementation checks used rustc/cargo1.95.0, native x86_64-pc-windows-gnullvm, bundled rust-lld and rust-mingw libraries, link-self-contained=yes. This is a real, isolated std-only component manifest and generated lockfile; no recovered workspace or dependency versions are invented. The selected source has no external crate dependencies. The build configuration follows https://doc.rust-lang.org/rustc/platform-support/windows-gnullvm.html. Linux compilation and machine-code comparison were not performed.

## Observations and value contract

contexts.json retains 29 complete actual unwind FDE contexts:10,326 bytes / 2,756 instructions. These are selected contexts, not a source-function or whole-component denominator. Capstone and GNU partitions agree for 29/29 contexts. No instruction bytes are normalized or credited as independently recompiled target code.

The Ctx entry is 0x4d93030..0x4d933b5 (901 bytes). A writer byte at +0xb selects map header 8d for canonical 1, sequence header 9d for canonical 0. Comparisons against 1 and against 0 are not interchangeable on arbitrary other bytes; the Rust API exposes only the two qualified modes. The fixed hardfork helper emits its own parent key and nested map 82 / sequence 92.

| Order/key | Source operand relative to Ctx input | Value route |
| --- | --- | --- |
| 1 hardfork_height | QWORD+0x10 | unsigned encoder0x57d00b0 |
| 2 hardfork | QWORD+0x18 and+0x20 | 0x4e0bdb0: version, round |
| 3 height | QWORD+0x28 | unsigned encoder |
| 4 tx_index | DWORD comparison at +0; QWORD+8 if tag==1 | unsigned Some, otherwise nilc0 |
| 5 round | QWORD+0x30 | unsigned encoder |
| 6 time | address+0x60 | 0x4e0da40 ->0x5307510 |
| 7 prev_time | address+0x6c | same formatter |
| 8 next_oid | QWORD+0x38 | supplied-key unsigned wrapper |
| 9 next_lid | QWORD+0x40 | same wrapper |
| 10 next_twap_id | QWORD+0x48 | same wrapper |
| 11 system_nonce | QWORD+0x50 | fixed-key wrapper0x4e0cab0 |
| 12 use_system_nonce | DWORD load+0x78; wrapper consumes low byte | valid bool 0/1 ->c2/c3 |
| 13 mac | QWORD+0x58 | unsigned wrapper0x4e0b920 |

These loads do not prove the original Rust struct size/alignment or physical bool/discriminant width. The abbreviation mac is not expanded. The independent Context/Option/bool types are a safe value API, not a native ABI declaration.

Unsigned values use fixint below 128, cc+byte below 256, cd+big-endian16 below 65,536, ce+big-endian32 below 2^32, cf+big-endian64 otherwise. The complete subwriters retain marker-before-payload append order and byte-swap instructions. Strings use fixstr below32, d9+u8 length below 256; the generic captured primitive also has da/db branches, but actual Ctx keys/timestamps need at most 32 bytes. Both modes include all thirteen values; map keys and nested hardfork keys follow the exact observed order.

## Timestamp qualification

0x5307510 formats the packed date at offset0, writes literal T, then formats the two u32 time words at +4/+8. It appends no timezone suffix. Constant String vtable0x64a46e0 has size 24 / alignment 8; write_str/write_char relocations bind0x526e2b0/0x526e1a0. Date/time callback slots0x64e1158/0x64e1160 bind0x1628bc0/0x162a760. The date bounds Location relocation points to a chrono/naive/internals.rs build path. This establishes a source-path attribution, not a Chrono revision or an unmodified public dependency identity.

The declared raw success profile is dateIndex=((packed_date as u32)>>3)&1023 <733, seconds<86400, nanos<2000000000. The lowest three date bits are ignored. The year is signed packed_date>>13. Index/2 supplies ordinal and index&1 selects common-year month lengths. The Gregorian relation independently regenerates all 731 calendar cells and both padding cells of the 733-byte captured table. Padding indices 0/1 format month/day00; this raw behavior is not a claim that such values are valid Chrono objects. Constructor invariants and the full original typed-value domain remain unproved.

Years 0..9999 have four zero-padded digits; other representable years use signed minimum width 5. Time is HH:MM:SS, with one second added and1e9 subtracted once when nanos>=1e9. Zero residual fraction has no suffix; otherwise divisible 1e6 -> 3 digits, divisible 1000 -> 6 digits, otherwise 9 digits. The format controls establish the sign-aware zero padding and widths. qualification.json gives finite integer proofs for all stated quotient domains, two full-u32 divisibility bijections,100 decimal pairs and10,000 four-digit years. It is algebra and calendar enumeration, not an instruction evaluator or captured-code emulation.

The Rust timestamp API rejects inputs outside this declared profile. That new validation error is not a recovered native Result variant or a replacement for target panic behavior.

## Errors and boundaries left open

Primitive success discriminant 2 is wrapped into Ctx 0x8000000000000004. Recoverable key/value/header failures are wrapped or forwarded with0x8000000000000000 and the observed payload. Primitive allocation failure sites distinguish before-marker and after-marker states; prior bytes can remain appended. The time adapter frees its temporary String after wire writing and has separate formatter-panic/unwind cleanup paths.

This implementation claims successful bytes only. It does not claim original allocator failure, allocation timing, partial-output state, panic/unwind, serializer-configuration layout, calling convention, vtable ABI, dependency revision, helper closure, code-byte or whole-ELF equivalence. No captured binary was run or emulated, and no unlicensed inferred source was used.

## Implementation, controls and results

src/node115-context-encoder implements the complete 13-field success profile, including typed raw timestamps rather than caller-supplied formatted strings. Its calendar relation is regenerated; captured code/data tables are not transplanted into Rust.

frozen-wire-cases.json was saved before the Rust implementation existed (SHA-2562c6c20be919e243915524a211804ddd5b1c8abc4c9cf2b97ff4f875113922d71). Its 32 whole messages cover both modes, Some/None, all unsigned-width fences, nested hardfork ordering, signed/extended years, both calendar kinds, leap-second carry, fraction widths and the31/32-byte string boundary. These are static target-derived expectations, not observed target execution outputs.

The 34 Rust tests pass: 32 whole messages plus raw-profile rejection and ignored-date-flag controls. Three separately mutated copies of our own Rust are rejected: the 128 fence, reversed hardfork members and8-digit nanos. rust-counterfactuals.json retains their failing test IDs and exit 101. Six Python evidence tests pass, including complete target regeneration and changed year/calendar/digit/key controls. Two independent optimized native builds yield identical rlib hashes; validation-precommit.json records them and the actual command outcomes.

A mandatory-check blocker was reproduced earlier on this exact base: test_exit_slot_mutation_rejected copied the 105,896,032-byte buffer on every relocation row, reaching its target only on row 52,495 (potential 5,559,012,199,840 bytes copied). This active RE-009 task needs the official full test command. The only supporting test change passes the same bytearray directly to struct.unpack_from, preserving the relocation, mutation, final bytes conversion and every assertion. The original 11 tests now complete and pass in 40.258 seconds. This is not a standalone tooling claim.

Precommit focused results are not a claim that the official whole repository command passed. Exact final-head doctor, verify/test/catalogue-check and reproduce outcomes belong in the PR and handoff records, including any failures or unreached checks. All component gates stay false. The next question is the Ctx decoder/encoder integration and original serializer/allocator/dependency closure.
