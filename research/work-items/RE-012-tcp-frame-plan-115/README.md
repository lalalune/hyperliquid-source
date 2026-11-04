# RE-012: node115 TCP header admission and chunk planning

## Question and new result

The active #115 tree has no independently authored TCP frame-policy library.
This packet follows a complete header through its actual helper into one
reader's size gate, flag selection and payload read interval. It adds
`src/node115-tcp-frame-plan`, a real dependency-free Rust library, rather than
claiming recovery of an entire async reader or node transport component.

Task/component: RE-012 / transport. Base main:
`8fd8db680ec4bfef40996e5616bce3d5156d0b86`. Target: Linux x86-64 node #115,
105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Historical PR #139 suggested the framing question; its #94 coordinates, copy
counts and claims are not migration evidence. All coordinates and data below
were freshly extracted from #115. No inferred unlicensed source is copied.

Observations are exact bytes, branches, fields, FDEs and relocations. TCP/header
and LZ4 labels are interpretations supported by captured source/diagnostic text.
The Rust structs, error type and range API are new, not recovered native types.

## Captured contract

| Observation | Native evidence | New API |
| --- | --- | --- |
| Five header bytes requested | `0x2b78112`, `0x2b78122` | `[u8; 5]` input |
| First four bytes reversed as u32; fifth byte loaded separately | `0x2b78225..0x2b78230` | `decode_header` |
| Actual helper output stores tag, length and flag at +0/+4/+8 | `0x2b78230..0x2b7823b` | scalar fields, no ABI claim |
| Two actual helper callsites | `0x2b78c42`, `0x2b78ec4` -> `0x2b780d0` | ordinary complete-header premise |
| Reader loads length/flag and reaches a shared size gate | `0x2b78c6c..0x2b78c7e`, `0x2b78f25`, `0x2b79038` | supplied current limit |
| Unsigned max >= length admits equality | `0x2b7903f`, `0x2b79043` -> `0x2b791c6` | `admit` rejects only greater lengths |
| Compare raw flag with exactly 1, store boolean | `0x2b791c6..0x2b791ce` | other flag values use plain route |
| Payload allocation/setup follows the selected gate | `0x2b791d3`, `0x2b79217..0x2b7922f` | allocation excluded |
| Completion branch precedes next read; unsigned min(remaining, 4000000) | `0x2b799e6..0x2b79a05` | `next_chunk` |
| Post-read transform branch and actual slot | `0x2b79aa3`, `0x2b79ace` -> slot `0x64e7790` -> `0x477f8c0` | dispatch description only |

The reader stores the zero-extended announced length at owner +0x58 and the
allocated logical length at +0x70; the completed counter is +0x78. On a next-read
arm, completed < announced <= u32::MAX, so completed + min(remaining, 4000000)
is bounded by the announcement and cannot overflow. The native capacity/alias
and helper postconditions remain premises; the new API returns intervals only.

A zero announced length is admissible at limit zero. Flag one still selects the
post-read transform, even for an empty payload. This is not a decompression
success claim. Unknown flag values are not rejected by this selected predicate.

## Evidence and independent methods

The entire artifact is authenticated before public collection. Unique,
non-overlapping unwind extents and complete instruction partitions are retained:

| Role | ELF VA range, end exclusive | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Header helper | `0x2b780d0..0x2b782d5` | 517 | 139 |
| Reader context | `0x2b788e0..0x2b79e2e` | 5,454 | 1,001 |
| Total retained context | | 5,971 | 1,140 |

Full GNU and LLVM exports agree with Capstone instruction addresses and raw
bytes. Only standalone LLVM LOCK display prefixes are joined to their next
instruction; no bytes or operands are masked. FDE/CIE bytes and LSDA addresses,
102 callsites, 131 direct branches, seven computed-dispatch tables, selected
unique relocation writers, source Locations and literals are retained in
`evidence.json`. All table targets land on decoded owner instruction boundaries.
Those inventories describe context, not implementation coverage or helper closure.
GNU readelf separately confirms both FDE headers in `readelf-selected-frames.txt`.

`context.py` uses an independently written PT_LOAD reader, rather than section
mapping, to recheck both complete body hashes. It binds the selected transform
slot and the actual RIP reference to `lz4 bytes over limit` in that helper.
This supports the LZ4 label without reconstructing its codec or native error ABI.
This supplemental context was added after the pre-Rust corpus freeze; the frozen
inputs, expectations and core collector are unchanged. Both methods are authored
here; no independent peer review is claimed.

## Frozen comparison and corruption controls

`freeze.py` generated inputs/expectations before `lib.rs` existed and refuses to
run with that source present. `corpus.json` binds the original collector,
generator, input and expectation digests. The 226,976 rows include every raw flag
byte at selected length/limit/counter boundaries, 4-million chunk transitions,
32/64-bit extrema and 4,000 seeded cases. A positional byte expansion and direct
interval oracle cross-check the captured-operand analytical relation.

The Rust driver receives only input bytes and integers, not expected results.
rustc 1.95.0 debug, optimized and repeated optimized builds each match all
226,976 rows; optimized library hashes repeat. All nine separately compiled
production mutations complete normally and disagree: endian reversal, strict
limit equality, truncating the u64 limit, two wrong flag rules, chunk cap,
maximum instead of minimum, a final empty read and a wrong range start.

Five below-identity target-operand counterfactuals change actual decoded policy
operands and produce changed observations. Six structural operand corruptions,
a duplicate parsed FDE-provider record and a truncated capture are rejected.
Structural/range locks are not described as semantic proofs. `results.json`
retains exact counts, tool/compiler identities, hashes and all control outcomes.
Raw inputs, expectations, command/compiler logs and every runner output are
retained in the ignored output directory and regenerate from the saved scripts.

## Reproduce

From the repository root, with authenticated LFS input, Python 3.14.5,
Capstone 5.0.7, GNU binutils 2.45 and LLVM 23.1.4 available:

```sh
python3 -B research/work-items/RE-012-tcp-frame-plan-115/verify.py \
  --rustc /path/to/rustc-1.95.0 --output work/tcp115-fresh
cargo +1.95.0 test --locked --offline --manifest-path src/node115-tcp-frame-plan/Cargo.toml
cargo +1.95.0 fmt --check --manifest-path src/node115-tcp-frame-plan/Cargo.toml
make doctor verify catalogue-check reproduce
make test
```

Use a fresh verification output directory. The library has a genuine Cargo
manifest and generated lockfile with no external dependency or build hook.
Only the newly compiled host library/driver/tests execute. No captured binary,
instruction evaluator, socket, network service or chain action executes.

The full unchanged baseline tooling/test sources passed 76 isolated unittest
files, 380 reported cases, three skip records and zero failed files. New Rust
has two separately passed boundary/sequence tests plus the frozen comparison.
`validation.json` fingerprints shared sources and actual local logs; it does not
claim a full-suite run on every later metadata revision. Final integration
checks and generated inventory updates are described in `VALIDATION.md`.

## Limitations and next question

The supplied header must represent the complete ordinary-return input. Actual
reads, readiness/error/pending paths, original future/Result/Vec ABI, allocation,
ownership/drop, concurrency, timeout/log effects, unwind, other reader copies
and the LZ4 body remain unresolved. Full owner listings do not close these gaps.
Synthetic input combinations need not be reachable from an original caller.
Finite scalar agreement is not target execution or original machine-code identity.

No byte-comparison credit or component acceptance gate is changed. Generated
inventory counts only describe one added Rust area/manifest/work item. Next:
close the selected read helper and transform result contracts before composing
this plan into an executable transport path.
