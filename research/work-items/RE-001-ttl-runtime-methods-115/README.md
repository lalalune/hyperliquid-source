# RE-001: pin node #115 TTL runtime methods

## Task and bounded question

Task **RE-001** (the node #115 function map). What do the three TTL
classes do at runtime -- `TtlMergeOperator`, `TtlCompactionFilter`
and `TtlCompactionFilterFactory` -- beyond the construction and
registration pinned by PR #4065? The TTL value format, how merges
strip, delegate and re-timestamp, how the filter decides expiry and
re-appends the timestamp, how the factory wraps its filter, what the
Configurable slots enforce, and what every vtable slot holds.

## Answer

A TTL value is **payload + a 4-byte little-endian timestamp suffix**.
Every runtime method strips the last 4 bytes before delegating to
the wrapped object and re-appends a timestamp afterwards.

| Method | Address | What it does |
|---|---|---|
| `TtlMergeOperator::FullMergeV2` | `0x6206610` | Strip existing + operands (short value -> `db_ttl_impl.cc:36`/`:45` error log, false), delegate to wrapped FullMergeV2 (slot 20), on success append the current time (`:86` on clock failure) |
| `TtlMergeOperator::PartialMergeMulti` | `0x6201c90` | Same pattern over the operand deque in 32-Slice chunks (`:108` short operand, `:126` clock failure) |
| `TtlCompactionFilter::Filter` | `0x6203520` | Expired -> kRemove; wrapped null -> kKeep; else delegate on the stripped value; a changed value gets the original timestamp re-appended |
| `TtlCompactionFilter::FilterV2` | `0x5d2e4a0` | kValue -> Filter mapping (keep/change/remove); kMergeOperand -> slot-20 delegate or keep; else keep |
| `TtlCompactionFilter::FilterV3` | `0x5d2f8a0` | kWideColumnEntity -> keep; else FilterV2 mapping |
| `TtlCompactionFilterFactory::CreateCompactionFilter` | `0x6202ba0` | Wrap the factory's own filter in a new `TtlCompactionFilter` (ttl + clock inherited) |
| Expiry helper | `0x6203400` | `(uint32)(last 4 bytes) + ttl < now`; ttl <= 0 never expires; the sum is 64-bit and does not wrap |
| `IsInstanceOf` (MO) | `0x6202520` | `"Merge By TTL"` or `Name()` or the short name |
| `IsInstanceOf` (CF) | `0x6202440` | `"Delete By TTL"` or `Name()` or the short name |
| `IsInstanceOf` (CFF) | `0x5d2e770` | Shared default: `Name()` or the short name (empty name never matches) |
| `PrepareOptions` (all three) | `0x6200b70` / `0x6200bf0` / `0x6200c70` | Resolve a null clock via `0x5fcf430`, then base `PrepareOptions` |
| `ValidateOptions` (all three) | `0x6200e10` / `0x6200cf0` / `0x6200d80` | Error on a null wrapped operator / clock (`"SystemClock required by ..."`, `"UserMergeOperator required by TtlMergeOperator"`), then base `ValidateOptions` |

- The error strings carry their `utilities/ttl/db_ttl_impl.cc`
  source lines: `:36` existing value, `:45` operand value, `:86`
  FullMergeV2 clock, `:108` PartialMergeMulti value, `:126`
  PartialMergeMulti clock.
- The clock is reached through an 8-level unrolled chain-walk on
  vtable slot 24 (`GetCurrentTime`, GOT canonical `0x64ed3e8` ->
  `0x5d4b100`); the first level whose slot-24 differs from the
  canonical is called. `Status` is 16 bytes with a hidden return
  pointer in `rdi`; `PosixClock::GetCurrentTime` (`0x5fe2230`) uses
  `time()`.
- `FullMergeV2` and `PartialMergeMulti` delegate through vtable
  slots 20 and 22; `Filter` delegates through slot 19 with the
  stripped slice; `CreateCompactionFilter` calls the wrapped
  factory's slot 20 and the `TtlCompactionFilter` C2 (`0x6202a10`)
  at `0x6202c01`.

## Vtables

All three vtables share the Configurable slots 2-13 and the
Customizable slots 14-16. Slots 17/18 are the same in every family:
slot 17 returns the wrapped object (null by default, `0x5d2ca00`),
slot 18 returns the short name (`""` by default, `0x5d2ca10`) --
the short names are `"max"`, `"put_v1"`, `"sortlist"`,
`"stringappendtest"` and `"PosixClock"` for the sibling classes,
and empty for all three TTL classes. `GetOptionsPtr` (`0x5d2e090`)
calls slot 17 to delegate option lookup to the wrapped object;
the default `IsInstanceOf` calls slot 18 as the alternate name.

- **TtlMergeOperator** (vtable `0x64d9558`, 25 slots, size 0x38):
  D2/D0, Configurable, `Name` -> `"TtlMergeOperator"`, `IsInstanceOf`
  `0x6202520`, slot 17 `0x6200940`, slot 18 empty, `FullMerge`
  default-false `0x5d2cd80`, `FullMergeV2` `0x6206610`,
  `PartialMerge` default-false `0x5d2cd90`, `PartialMergeMulti`
  `0x6201c90`, `AllowSingleOperand` false `0x5d2cda0`,
  `ShouldMerge` false `0x5d2cdb0`. Fields: +0x08 vector<string>,
  +0x20 `shared_ptr<MergeOperator>`, +0x30 `SystemClock*`.
- **TtlCompactionFilterFactory** (vtable `0x64d9718`, 21 slots, size
  0x40): D2/D0, Configurable, `Name` ->
  `"TtlCompactionFilterFactory"`, shared-default `IsInstanceOf`,
  slot 17 `0x6200920`, slot 18 empty, slot 19 `0x5d2ca70`
  (`arg == 1`), `CreateCompactionFilter` `0x6202ba0`. Fields: +0x08
  vector<string>, +0x20 ttl, +0x28 `SystemClock*`, +0x30
  `shared_ptr<CompactionFilterFactory>`. The qword at `0x64d97c0`
  has no relocation: it is the `DBWithTTLImpl` header, not a 21st
  slot.
- **TtlCompactionFilter** (vtable `0x64d9630`, 27 slots, size 0x40):
  D2/D0, Configurable, `Name` -> `"TtlCompactionFilter"`,
  `IsInstanceOf` `0x6202440`, slot 17 `0x62008e0`, slot 18 empty,
  `Filter` `0x6203520`, `FilterMergeOperand` default-false
  `0x5d2ca30`, `FilterV2` `0x5d2e4a0`, `FilterV3` `0x5d2f8a0`,
  `PrepareBlobOutput` kKeep `0x5d2ca40`, `IgnoreSnapshots` true
  `0x5df72f0`, `IsStackedBlobDbInternalCompactionFilter` false
  `0x5d2ca50`, slot 26 returns 8 (`0x5d2ca60`, C++ name open).
  Fields: +0x08 vector<string>, +0x20 `const CompactionFilter*`,
  +0x28 owned unique_ptr, +0x30 ttl, +0x38 `SystemClock*`.

Slot-name notes: MO slot 19 is `FullMerge` by the PutOperator
behavioral witness (`0x61f4d60` assigns the deque's last operand to
`*new_value` -- last-operand-wins Put semantics) and the header
declaration order; MO slots 23/24 are `AllowSingleOperand` /
`ShouldMerge` (both defaults return false in the published
headers); CF slots 20/23/24/25 are `FilterMergeOperand` /
`PrepareBlobOutput` / `IgnoreSnapshots` (default true in 8.1.1,
matching 9.5.2) / `IsStackedBlobDbInternalCompactionFilter` by
header order. The catalogue does not name these slots. Header
defaults differ across RocksDB versions, so these identities rest
on the binary behavior plus the 8.1.1-era order, not on header
order alone.

## Evidence

- `records.json` -- semantic records only. Instruction-level detail
  lives in the verbatim objdump excerpts; mnemonics such as
  `endbr64` are genuine instructions present in the target binary,
  not placeholders.
- `excerpts/` -- 44 whole-function verbatim objdump files, produced by
  `export_excerpts.py` with
  `objdump -d --start-address=<start> --stop-address=<stop> work/hl-node-115.bin`
  run from the repository root.
- `frames.txt` -- the 44 FDE ranges, checked against a fresh frame dump.
- `callers.tsv` -- every pinned routine's direct calls, tail jumps,
  lea references and RELATIVE addends, with the enclosing FDE.
- `relocations.txt` -- the RELATIVE records for the three vtables
  (headers, typeinfos, every slot), the typeinfo names, the GOT
  canonicals (`0x64ed3e8`, `0x64ecff0`, `0x64ed0b8`) and the
  `DBWithTTLImpl` boundary.
- `census.py`, `export_excerpts.py`, `gen_records.py`, `verify.py` --
  the scripts that produced and check this packet.
- `MANIFEST.sha256` -- SHA-256 of every packet file except itself.

## Verification

```
python3 research/work-items/RE-001-ttl-runtime-methods-115/verify.py
```

Checks: binary digest vs provenance, manifest, excerpt regeneration
byte-for-byte, every excerpt instruction byte-for-byte vs the raw
binary, three seeded random gate spots (`0x620691b`, `0x62019c8`,
`0x6200d0c`) byte-for-byte vs a fresh objdump run and the raw binary,
frames, relocations, typeinfo names, literals, the movabs legacy
names in the IsInstanceOf excerpts, census reproduction, records
regeneration, the full vtable maps, the caller needles, and the
model tests (`tests/test_ttl_runtime_methods_115.py`,
405 checks). Prints `ALL CHECKS PASSED` on success.

## Model

`tools/ttl_runtime_methods_115.py` +
`tests/test_ttl_runtime_methods_115.py` (405 checks): the TTL value
format and timestamp round-trip, the expiry helper (including the
no-wrap 64-bit sum and the ttl <= 0 rule), FullMergeV2 and
PartialMergeMulti strip/delegate/re-timestamp with the :36/:45/:86
and :108/:126 error paths, Filter and FilterV2/FilterV3 decision
mapping, CreateCompactionFilter wrapping, Prepare/Validate option
rules, IsInstanceOf matching for all three classes, and seeded
random cross-checks against an independent reference.

## Environment limits

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so the
repository gates (`make verify`, `make test`, `make catalogue-check`)
cannot be run here; the packet's own `verify.py` is the check that
was run. The base `PrepareOptions`/`ValidateOptions`, the clock
resolver, the merge-error logger and the ValidateOptions error
builder are cited by address and behavior, not re-derived; the
constructors and registration are cited from PR #4065, the
SystemClockWrapper chain-walk from PR #3902.

## Open unknowns

- The C++ names of vtable slots 17 (wrapped-object accessor) and 18
  (short-name accessor) are open; both are pinned by behavior,
  cross-class census and callers.
- MO slot 19 is FullMerge by the PutOperator behavioral witness and
  the header declaration order; the catalogue does not name it.
- MO slots 23/24 are AllowSingleOperand/ShouldMerge, CF slots
  20/23/24/25 are FilterMergeOperand/PrepareBlobOutput/
  IgnoreSnapshots/IsStackedBlobDbInternalCompactionFilter, by header
  declaration order; the catalogue does not name them.
- CF slot 26 returns the constant 8; its C++ name is open.
- CFF slot 19 takes an int and returns arg == 1; its C++ name is open.
- The exact C++ names of `0x5fcf430` (clock resolver), `0x5fceda0`
  (merge-error logger) and `0x61cf670` (ValidateOptions error builder)
  are open.
- The +0x08 field of the MergeOperator and CompactionFilterFactory
  objects is recorded as a `std::vector<std::string>` by shape
  (PR #4065); only the CompactionFilter's is proven by its ctor
  unwind path.
