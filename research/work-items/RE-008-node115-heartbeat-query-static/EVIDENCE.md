# RE-008: Node115 heartbeat query, collection and row classification

- Component: `consensus`; bounded static research, no gate requested.
- Target: Linux x86-64 hl-node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository/reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Question: which actual115 code connects the heartbeat source-location records
  to queried rows, and what do its tag stores, numeric branches and age helper read?
- Included: nine complete unwind-described extents, two source-location records,
  selected data, all 76 decoded call sites (including unresolved register calls).
- Excluded: full consensus mapping, state update/decay, original types/names,
  calendar source identity, sorting comparator, allocator/import/logging closure,
  Rust implementation, target execution/emulation, node/network acceptance.

## Reproduce

From the repository root, with an already authenticated/materialized capture:

```sh
python3 -B research/work-items/RE-008-node115-heartbeat-query-static/verify.py \
  --target artifacts/node/115/hl-node --objdump objdump \
  --output work/heartbeat-query-proof.json
make doctor
make verify test catalogue-check
make test
make catalogue-check
make reproduce
```

The separate test/catalogue commands retain their own outcomes if verify stops
at its input-authentication prerequisite. Do not treat a failed prerequisite as
successful verification or rerun an identical failed whole suite automatically.
Python 3.12.1; initial GNU objdump 2.47; Capstone wheel 5.0.9 reports binding 5.0.7,
API[5,0,1280]. Complete instruction address/raw-byte pairs agreed between the two
original decoders. `verify.py` reparses actual FDE/CIE/RELA records and reruns GNU
against the frozen Capstone address/byte partition; it does not reimport Capstone.
Pinned repository parser hashes are in `native.json`. No pip install, network,
private data, target execution or emulator is needed. GNU commands per extent:
`objdump -d --wide --insn-width=16 -M intel --start-address=<VA> --stop-address=<VA> <target>`.
Raw disassembly header paths alone were replaced with `<authenticated-node115>`;
instruction bytes, operands and numeric addresses were not normalized or masked.

The original dual-decode and comparator completed without timeout. `result.json`
records the comparator result and deliberately corrupted metadata controls.
`MANIFEST.sha256` hashes the committed payload bytes. It is not a signature or a
replacement for authenticating the capture under `provenance/artifacts.json`.

## Native bounds and source attribution: observations

All coordinates are ELF VAs before runtime relocation, not file offsets or
runtime ASLR addresses. The checker resolves each range through exactly one
file-backed section and requires its complete actual FDE and CIE metadata.
An FDE is an unwind extent, not proof of an original source-function boundary.

| Unwind extent `[start,end)` | Bytes | Decoded instructions |
| --- | ---: | ---: |
| `0x162a290..0x162a42b` | 411 | 112 |
| `0x4d55380..0x4d554f6` | 374 | 88 |
| `0x4dda030..0x4dda626` | 1526 | 319 |
| `0x57d37c0..0x57d3a38` | 632 | 154 |
| `0x5a30130..0x5a305da` | 1194 | 258 |
| `0x5a71aa0..0x5a71d90` | 752 | 169 |
| `0x5a71e20..0x5a71ed9` | 185 | 48 |
| `0x5a71ee0..0x5a722ec` | 1036 | 172 |
| `0x5b72830..0x5b72b2e` | 766 | 168 |

Total: **9 distinct extents, 6,876 target bytes, 1,488 address/byte pairs**.
No denominator for the whole heartbeat module or consensus component is known.
Zero Rust-source/target comparisons; zero registered byte-coverage windows;
zero normalized-only matches; zero acceptance gates changed. These are static
decoder pairs, not reconstructed-code identity matches.

The two `.rela.dyn` RELATIVE records at `0x64b8cf0` and `0x64b8d08` both resolve
to the 39-byte `node/src/consensus/heartbeat_tracker.rs` at `0x430c77`.
Their adjacent length/line/column fields are respectively 208:39 and59:39.
Full decoding validates LEAs at `0x5a71e3d` and `0x5a720fe` referencing those
records from the 185-byte and 1036-byte extents. This source association does not
identify every callee as first-party heartbeat source or recover a source revision.

## Connected query path: observations

1. `0x5a71e20` saves its input/output pointers, calls `0x57d37c0` at
   `0x5a71e47` with a pointer at self+0xb0 and the208:39 location. The extent of
   that callee is decoded, but its complete configuration/logging contract is open.
   At `0x5a71e54`, GOT `0x64e0990` resolves by RELATIVE relocation to `0x1629690`.
   The query constructs a 96-byte frame carrying selected input lanes, self+0x148,
   self+0xb0 and a pointer to the provider's 12-byte result. Do not name the clock
   or original frame type from these observations alone.
2. Direct call `0x5a71ec3 -> 0x4d55380`; direct call
   `0x4d553cc -> 0x5b72830`. The latter calls `0x5138730` to obtain keys and
   `0x5a30130` to classify each row. It skips raw tag3; other results move as 40-byte
   rows. Empty output is cap0/ptr8/len0-shaped; initial allocation is 160 bytes
   for four rows. Original collection/allocator ABI is not recovered.
3. `0x4d55380` has a count-dependent branch at 2 and 21, calls `0x53eb8e0` or
   GOT`0x64eb268` on those paths, then `0x5b2cf00`. These are sort/processing
   leads, not a recovered ordering contract. Afterward a length greater than 64
   takes `0x5169120` and writes `0x8000000000000000` in the output's firstword;
   the other branch calls `0x580ade0` and copies 32 bytes. Original return types,
   error meaning and helper effects remain open.
4. Source59:39 extent `0x5a71ee0` uses literal `validator_latency_ema` at
   `0x93b1d7` length 21, calls through GOT`0x64e87c0 -> 0x5a71aa0`, and copies
   a 0x198-byte constructed object. `0x5a71aa0` traverses keys, constructs rows
   containing repeated 12-byte provider results and literal f64 bits
   `0x4066800000000000` (180.0), then calls `0x4dda030` for insertion.
   The latter's 1526-byte extent is retained, but full tree/layout semantics
   are not closed. Constructor unwind paths and all external callees remain
   distinct from the normal-return observations here.

`native.json` records each decoded call's raw bytes and direct destination or
RIP slot plus actual relocation list. Register calls retain an unresolved operand;
the record never chooses an arbitrary FDE or invents an indirect call target.
Matching a call-site relocation is not proof of the callee's behavior.

## Per-row output stores and numeric branches: observations

`0x5a30130` takes an output pointer, a three-pointer context and a 20-byte key.
The context supplies a map-like object, configuration pointer and 12-byte current
provider result. It supports two map representations; their lookup/ownership
semantics remain open. Below, entry means the computed found-entry pointer,
not an identified Rust struct. On normal-return paths:

| Rawtag at output+24 | Writes proven here | Branch |
| --- | --- | --- |
| 0 | key20; payload+32 unwritten | lookup misses |
| 2 | key20; f64 payload+32 | sanitized ratio ordered-greater than config+0x18 and byte config+0x20 is zero |
| 1 | key20; f64 age payload+32 | age ordered-greater than 180.0 after the ratio branch does not returntag2 |
| 3 | only tag; key/payload unwritten | remaining age branch; collector skips this tag |

The 4 bytes at output+20 are not initialized by these stores. Neither unwritten
payloads nor padding are zero-valued fields or a defined wire format. The flag
at config+0x20 is deliberately unnamed; a `dry_run` label is not established.

- Denominator is f64 entry+0x18. Ordered zero (including negativezero) takes
  ratio+0 without reading the numerator. Orderedpositive reads entry+0x10 and
  divides. Negative/NaN denominator branches to a diagnostic call through
  GOT`0x64df730`; no successful return for that path is asserted here.
- Instructions `0x5a302ba..0x5a30319` and `0x5a30510..0x5a30563` classify
  the ratio's raw bits, using masks`0x7fffffffffffffff`,
  `0xfff0000000000000` and`0x000fffffffffffff`. Inference from these branches:
  positive finite values are retained, negative nonzero/NaN/infinities become
  +0, and existing signedzeros are retained. This is a static interpretation,
  not executed floating-point or exception-state validation.
- `ucomisd`/`jbe` at `0x5a303af` sends equality and unordered comparison with
  config+0x18 to the age route. A strict orderedgreater test is required for tag2.
  Logging calls may occur before/after it; their effects/panics are not closed.
- `0x5a3047d` calls GOT`0x64e0fc0`, whose actual RELATIVE destination is
  `0x162a290`. Its two 12-byte operands are the current provider result and
  entry+0x58. All 411 bytes of the helper are decoded. It reads encoded fields,
  indexes a 400-byte table at`0x46bcaa`, does calendar/seconds/nanoseconds-shaped
  arithmetic and has a diagnostic branch. Its source dependency/version, exact
  admissible encoded-time domain and exceptional cases are **unresolved**.
- On return, RAX is treated as signed64 and EDX as signed32. When RAX<0 and
  EDX>0, RAX increments and EDX subtracts 1,000,000,000 (32-bit arithmetic).
  `cvtsi2sd`, `divsd` by 1e9 at`0x458d50`, then `addsd` form an age-shaped f64.
  `maxsd` with +0 clamps it. An equality branch against +infinity at`0x459010`
  leaves +0; the final comparison uses 180.0 at`0x4597f8`, with `ja` to tag1.
  Calling these fields seconds/nanoseconds is an interpretation of the
  constants/conversions, not proof of an original time type or source identity.

## Validation, negative controls and limits

The checker binds complete instruction partitions to actual target bytes,
unique exact FDEs/CIEs, both source records and their LEA instruction starts,
all calls/relocations, three f64 constants and the 400-byte helper table.
It reruns GNU for every complete extent and compares all 1,488 pairs with the
frozen independently decoded Capstone partition. Metadata corruption controls
exercise wrongidentity/bounds/CIE, missing/misaligned/changed instructions,
source fields/path, constant/table and call metadata. A rejected record tests
the evidence checker; it is not a behavioral test of the captured node.

No captured instruction was executed or emulated. No original Rust source was
recovered or copied; no unlicensed inferred-source reference was used. New
research/checker code is independently authored under the repository MIT terms;
captured binary evidence retains its upstream rights. No reconstructed Rust,
Cargo graph, two-build result, source comparison, module completeness, runtime
safety or current-network support is claimed. Full component gates stay false.

Before this packet there was no target-bound record of this connected 115 path
in this intake. After it there is a reproducible bounded static map and an
explicit numeric/output-store hypothesis; a falsified record is rejected.
Next question: bind the configuration initialization and encoded-time domains,
then independently reconstruct the admitted-domain classifier with frozen
boundary expectations. Recover sort ordering, map updates and unwind/helper
closure before joining it to consensus state transitions.
