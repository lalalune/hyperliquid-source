# RE-005: Node115 asset metadata JSON writer

- Component: serialization; RE-012 API association is a lead, not a recovered endpoint.
- Target: Linux x86-64 hl-node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
- Research base: 05bc2de303c05525b71e7e257426e741bc66a390.
- Bounded question: recover the ten-field logical successful JSON contract of ELF VA 0x2f186b0..0x2f1890c, including default omission and value formatting.
- Result: independently authored Rust component, frozen whole records and reproducible static evidence. This is partial reconstruction under the repository scope, not a production defect claim. No gate change.

## Before and after

The base has no src/node115-asset-metadata-encoder crate or this work item. The captured entry is a complete 604-byte, 145-instruction FDE, not a string-search window. The new crate emits the ten fields in their observed order. The expected corpus was frozen before this metadata implementation existed; its SHA-256 is 4d530386a90634c57f40c4dc047c996dcafe648088f9abcd7917f81f51f816c6.

The 223 complete expected messages comprise 144 combinations of the canonical omission modes, 54 binary64 cases, eight UTF-8/control/name cases, six unsigned integer boundaries and eleven date/time cases. These are independent calculations grounded in the static contract, not captured runtime outputs. They do not establish whole-node equivalence.

## Observations: entry and value paths

All addresses below are original ELF VAs; native.json also records file offsets and whole-FDE hashes. Native code/data were read and disassembled, never executed or emulated.

| Order / key | Input offset | Value path | Omission observed in entry |
| --- | --- | --- | --- |
| szDecimals | +0x3d | u8, field 0x2ec7750 | mandatory |
| name | +0x10 | string carrier, field 0x2ec25a0, escape 0x2ecabd0 | mandatory |
| maxLeverage | +0x3c | u8, field 0x2ec0710 | mandatory |
| marginTableId | +0x28 | u32, 0x2ec2190 -> 0x2ede440 | mandatory |
| onlyIsolated | +0x38 | boolean field 0x2ebc090 | byte zero |
| isDelisted | +0x39 | boolean field 0x2ebc090 | byte zero |
| marginMode | +0x3a | 0x2f19810 -> 0x2ec8930 -> 0x2edfbb0 | byte zero |
| growthMode | +0x3b | 0x2f19850 -> 0x2ec3be0 -> 0x2edfa70 | byte ONE |
| lastFeeScaleChangeTime | +0x2c | 0x2f19890 -> 0x2ec99e0 -> 0x2eabf70 | packed date dword zero |
| deployerFeeScale | tag +0, payload +8 | 0x2f19910 -> 0x2ec4170 -> 0x2edf980 | qword tag zero |

The input has a String-like 24-byte carrier at +0x10. The original type name and ownership/constructor invariants are not recovered. AssetMetadata is our logical API name, not a recovered native type declaration.

Margin values 0/1/other select normal/noCross/strictIsolated. Growth values 0/1/other select enabled/disabled/blocked. The independent API exposes three canonical variants; arbitrary invalid native discriminants are outside it. False booleans, Normal, Disabled and absent optional values are omitted. In particular, growth's default is 1, not 0.

The entry writes an opening brace, initializes compound state, calls the first four field writers, conditionally calls the remaining six, then writes the closing brace. It checks error returns and has state/error/allocation branches. The component implements a fresh logical success result, not captured partial-append or Result-pointer behavior.

The JSON escape path uses relocation 0x64e13d8 -> 0x946dcc: all 256 byte classes are independently checked. ASCII controls use lowercase hexadecimal or the b/t/n/f/r escapes; quote and backslash are escaped. Relocation 0x64e13e0 -> 0x946ecc supplies the first 16 bytes 0123456789abcdef. Bytes after that alphabet are unrelated pool data. Valid UTF-8 non-ASCII bytes are retained without normalization. Raw invalid strings are outside the API.

The unsigned writer at 0x2ede440 loads eax from dword ptr [rdi]. The packet includes the complete numeric field/writer FDEs, not only the high-level key calls.

## Fee formatting: evidence and inference

deployerFeeScale is a JSON STRING. Its serializer calls 0x44a61d0 through relocation 0x64e5bd8. That helper constructs format arguments, uses the eight-byte descriptor c5200000700a0000 at VA 0x459898, trims trailing zeroes while preserving one digit after the decimal point and normalizes exact -0.0 to 0.0.

Relocation 0x64e0a78 selects callback 0x1688740. Its precision-present branch tests flag 0x10000000, loads the raw u16 precision from Formatter+0x16 and tail-calls 0x167bc20 without adding one. Its absent-precision branch tail-calls 0x167c040 with edx=0. Both complete common helper FDEs are retained.

Source correspondence to the independently pinned Rust standard library supports Display with precision 10:
https://github.com/rust-lang/rust/blob/59807616e1fa2540724bfbac14d7976d7e4a3860/library/core/src/fmt/float.rs

The documented fixed precision and nearest-even rounding reference is:
https://doc.rust-lang.org/std/fmt/#precision

format_witness.py compiles seven independent Rust snippets to AMD64 COFF data, without executing them. Precision 10 matches the descriptor; precision 9, precision 11, default and signed-plus controls do not. BOTH .10e and .10E also match it. Thus the descriptor alone does not distinguish Display from exponential formatting: the callback/control-flow evidence is a separate obligation.

reference_cases.py uses integer/rational decomposition of binary64, scaling by 10^10 and quotient/remainder nearest-even rounding. It covers signed zero, subnormal/normal boundaries, maximum finite values, infinities, NaN payloads and exact half ties with adjacent bit patterns. Rust uses its standard library formatter; no floating conversion algorithm was copied. Native dependency revision and a universal instruction-level proof of every rounding path remain unknown. Accepting every binary64 bit pattern in our API is not a claim that those unknowns are closed.

## Timestamp reuse and real dependency

The timestamp adapter reaches callback 0x2f06ec0, which prints date, T (0x54), then time. Its relocations 0x64e1158/0x64e1160 resolve to 0x1628bc0/0x162a760 on this exact #115 target. These are the same helpers already recovered in the public context encoder.

The component has one REAL path dependency: the byte-identical MIT context encoder from published commit 255cb2ccd9c9443c9bb5745f04ecc1c73627b10b, retained under research/imported with original files, license and per-file provenance. No fake package, stub or reconstructed original Cargo graph is asserted. Only its Timestamp and timestamp_text are used. No additional registry dependencies are introduced. This reuse earns no new timestamp or Ctx reconstruction credit.

The retained raw-integer timestamp profile accepts index<733, seconds<86400 and nanos<2,000,000,000, including table padding not asserted to be constructor-valid dates. Some(packed_date=0) is rejected locally because the metadata entry treats that native niche as absence. The independent API validates before output and returns its own safe profile error; original errors, allocation failure, panic/unwind and prefix mutation remain unclaimed.

## Reproduce

Run from the repository root with the authenticated capture materialized through the normal project LFS preparation. Install no unpinned target executables.

    python3 -B research/work-items/RE-005-asset-metadata-encoder-115/extract.py --target artifacts/node/115/hl-node --objdump /absolute/path/to/objdump --output /chosen/output
    python3 -B research/work-items/RE-005-asset-metadata-encoder-115/test_evidence.py -v
    python3 -B research/work-items/RE-005-asset-metadata-encoder-115/reference_cases.py --output /chosen/output/frozen.json
    python3 -B research/work-items/RE-005-asset-metadata-encoder-115/format_witness.py --rustc /absolute/path/to/pinned/rustc --out-dir /chosen/output/format-witness
    cargo test --offline --locked --manifest-path src/node115-asset-metadata-encoder/Cargo.toml --target-dir /chosen/output/debug
    cargo test --release --offline --locked --manifest-path src/node115-asset-metadata-encoder/Cargo.toml --target-dir /chosen/output/release
    cargo clippy --offline --locked --manifest-path src/node115-asset-metadata-encoder/Cargo.toml --all-targets --target-dir /chosen/output/clippy -- -D warnings
    cargo fmt --manifest-path src/node115-asset-metadata-encoder/Cargo.toml --all -- --check
    make doctor
    make verify test catalogue-check
    make reproduce

Observed static tools: Python 3.12.1, Capstone 5.0.7 and GNU objdump 2.47, AMD64/intel syntax. The extractor authenticates the whole target SHA, parses actual FDE bounds and compares complete byte/instruction partitions between both decoders. It exports all RIP-relative references and relevant dynamic relocations. This decoder agreement is not a compiled-Rust comparison.

Actual builds use rustc 1.95.0 (59807616e1fa2540724bfbac14d7976d7e4a3860), LLVM 22.1.2, x86_64-pc-windows-gnullvm, its rust-lld and -C link-self-contained=yes. CARGO_BUILD_JOBS=2, CARGO_INCREMENTAL=0, offline caches and all temporary/build output paths are explicit. Windows native builds do not establish Linux ABI or ELF identity. The witness enforces this compiler executable identity.

## Results, controls and limits

See validation.json and raw-controls.txt for actual results, source hashes and failure history. Debug and release each pass two integration tests covering all 223 messages plus four rejected local timestamp inputs. Clippy denies warnings; format check passes. Ten Python evidence checks include eight decoded-record corruption controls, a positive contract and the frozen adapter. Seven format descriptor controls behave as declared. The frozen reference regenerates byte-for-byte.

Three real Rust counterfactuals (precision 9, unquoted fee, wrong growth default) each fail the frozen-whole-record test with Cargo exit 101. They compile and execute our own code only. These failures demonstrate sensitivity of the comparator, not captured runtime behavior.

The selected denominator is 49 complete FDEs / 12,921 bytes / 3,312 instructions, including reused/shared helpers. GNU and Capstone partitions agree for 49/49; 47 relevant dynamic relocations are exported. No raw-equal/normalized Rust-vs-target windows were measured and no masks were applied. A whole-component denominator, caller/API ownership, original ABI/errors, transitive allocator/error/float helper closure and complete source dependency graph remain unresolved.

A known unchanged base test repeatedly copies the 105,896,032-byte capture inside a 52,495-entry relocation loop. The exact base control previously stopped on its 180-second no-progress limit (exit 124). That test and target bytes are unchanged here. Its independently submitted fix is outside this PR. The full make test run is not repeated without new resolution evidence, and no all-suite pass is claimed; the initial ordinary PR discloses this mandatory-check gap for review. Other required checks and exact final-head results are reported in the PR.

No captured node/visor execution or emulation, networking, signing, keys or user data were used. All full-scope gates stay false. Next question: establish concrete caller ownership and recover native constructors/errors, then close the precise native float dependency before any wider runtime-equivalence claim.
