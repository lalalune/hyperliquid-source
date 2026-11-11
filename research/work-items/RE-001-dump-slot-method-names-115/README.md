# RE-001: dump slot method names (node #115)

## Bounded question

Name, for node #115, the C++ methods behind the vtable slot calls in
`ColumnFamilyOptions::Dump` (0x60b50c0) and the sole host that drives
the dump. This resolves the open unknowns left by PR #4286 (which
pinned the dump's 93 lines, the leveled helper, and the enum name
function, but left the slot-call targets unnamed).

## Answer

| Dump call | Slot | Method | Evidence |
| --- | --- | --- | --- |
| helper 0x5fceda0, level 5 | Logger 3 (0x18) | `LogHeader(const char*, va_list)` | EnvLogger 0x5fcc200 forwards to slot 5 with level 1 (INFO_LEVEL); AutoRollLogger overrides at 0x6057000 |
| helper 0x5fceda0, other levels | Logger 5 (0x28) | `Logv(InfoLogLevel, const char*, va_list)` | Shared 0x5fcd400: gate `level >= log_level_` (+0x11), else jump to core 0x5fcd2c0 |
| helper 0x5fceda0 pre-gate | Logger 8 (0x40) | `GetInfoLogLevel() const` | EnvLogger 0x5fcc220 returns the byte at +0x11; AutoRollLogger 0x60552e0 delegates to the wrapped logger |
| line 7, `table_factory options: %s` | TableFactory 4 (0x20) | `GetPrintableOptions() const` | BBT 0x60da1f0, Cuckoo 0x615aca0, Plain 0x6192d70; each formats its options via snprintf |
| line 62, `table_properties_collectors: %s` | CollectorFactory 20 (0xa0) | `ToString() const` | Base 0x60b1ea0 calls Name (slot 0x70); CompactOnDeletion overrides at 0x61fb370 |
| line 87, `Options.blob_cache: %s` | Cache 2 (0x10) | `Name() const` | LRUCache 0x5d3a950 -> `LRUCache`; ChargedCache 0x5db68c0 -> `ChargedCache`; base is pure virtual |
| line 88, `blob_cache options: %s` | Cache 25 (0xc8) | `GetPrintableOptions() const` | Base 0x5d3f6c0 returns `""`; LRUCache 0x5d3f210 formats; secondary adapter 0x5d42460 delegates |
| host 0x5d954b0 | — | `ColumnFamilyData::ColumnFamilyData(...)` | `[%s:619]` header log, `< 10` CF gate, Dump call at 0x5d95e69, then RecalculateWriteStallConditions |

Supporting identifications, all pinned by the same evidence:

* **Logger slots 0-10** (env.h order, behaviorally confirmed): 2 =
  `Close()` (0x5fcc410, shared; idempotent via the `closed_` flag at
  +0x10, delegates to slot 10 `CloseImpl()` 0x5fceae0), 4 =
  `Logv(const char*, va_list)` (0x5fce280), 6 =
  `GetLogFileSize()` (0x5fcced0), 7 = `Flush()` (0x5fce130), 9 =
  `SetInfoLogLevel` (0x5fcc230, stores +0x11). The level byte is
  `this+0x11`; the closed flag is `this+0x10`. Only two Logger
  classes exist in the binary (EnvLogger, AutoRollLogger); no
  PosixLogger vtable.
* **Logger destructor roles.** Slot 0 holds the complete-object destructor
  (D1), and slot 1 holds the deleting destructor (D0). The EnvLogger D0
  at `0x5fcfde0` ends by deleting `this` with size `0x140` at `0x5fcffd4`.
  AutoRollLogger D0 at `0x6057d00` calls `0x60576b0`, then deletes `this`
  with size `0x290` at `0x6057d16`. The D0/D1 labels follow the
  [Itanium C++ ABI](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#ctor-dtor-name).
* **EnvLogger emission rule.** A level-L message is emitted iff `L >=
  log_level_`. A level-5 (HEADER) message is emitted iff `1 >=
  log_level_`, because LogHeader re-gates through `Logv(INFO_LEVEL)`.
  The helper pre-gates on slot 8 (`ja ret` when `log_level_ >
  level`); the sibling helper 0x5fceea0 calls slot 3 with no level
  check.
* **AutoRollLogger header route.** The body at `0x6057000` returns
  when the wrapped logger at `this+0xb8` is null. Its non-null path
  calls wrapped slot 4 at `0x60570f8`. Downstream emission remains
  unresolved. The EnvLogger threshold model applies to EnvLogger.
* **TableFactory slots** (configurable.h + customizable.h order):
  2 = `GetOption` (shared 0x609d760), 3 = `AreEquivalent`, 4 =
  `GetPrintableOptions`, 5 = `PrepareOptions`, 6 =
  `ValidateOptions`, 7 = `GetOptionsPtr`, 8 =
  `ParseStringOptions`, 9 = `ConfigureOptions`, 10 = `ParseOption`,
  11 = `OptionsAreEqual`, 12 = `SerializeOptions`, 13 =
  `GetOptionName`, 14 = `Name()`, 15 = `GetId()` (shared 0x5d32a30).
  `GetOption` has an "id" special case: when the requested name is
  exactly `"id"` it calls slot 15 (`GetId`) and returns it as the
  value -- which independently confirms slot 15 is `GetId`.
* **CollectorFactory slot 20 is `ToString` because** Configurable
  occupies slots 0-13, Customizable adds Name(14) GetId(15)
  IsInstanceOf(16) Inner(17) NickName(18), and the factory adds
  CreateTablePropertiesCollector(19) then ToString(20). The protected
  virtual `NickName()` is the slot that pushes ToString to 20.
  CompactOnDeletion's full map (slots 0-20) is in vtables.tsv,
  including Inner() returning nullptr (0x5d2ca00) and NickName()
  returning "" (0x5d2ca10, literal at 0x4376fd).
* **Devirtualization guards in the dump.** Blob-cache: 0x60b6235
  loads slot 25 and compares it against GOT 0x64ecd20 (RELATIVE ->
  0x5d3f6c0, the base default); equal -> empty string, else call
  slot 25 (cold block 0x60b7080). Collector: 0x60b5d70 loads slot 20
  and compares against GOT 0x64edca8 (RELATIVE -> 0x60b1ea0, the base
  ToString); match -> Name() fast path, mismatch -> cold block
  0x60b64c0 calls slot 20. Neither base function has a direct caller
  in the binary: they exist only as comparison targets (and, for
  ToString, as the inherited implementation for classes that do not
  override it -- none present in the binary).
* **Host.** The dump's sole caller is the ColumnFamilyData ctor
  (FDE 0x5d954b0..0x5d96890), which itself has exactly two direct
  callers (0x5d96cf8, 0x5d972ab; enclosing functions at 0x5d969c0 and
  0x5d97220). Gate: `NumberOfColumnFamilies() < 10`, else the
  `[%s:624] (skipping printing options)` log.

## Evidence

* Artifact: `work/hl-node-115.bin`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (provenance/artifacts.json, `node/115/hl-node`).
* 31 whole-function verbatim excerpts in `excerpts/`, each produced
  by `objdump -d --start-address=<start> --stop-address=<stop>
  work/hl-node-115.bin` over the FDE range in `frames.txt`
  (regenerate with `export_excerpts.py`). Instruction mnemonics such
  as `endbr64` are genuine instructions present in the target binary,
  not placeholders.
* Four excerpts are re-shipped byte-identical from PR #4286's packet
  (`research/work-items/RE-001-options-dump-115/`): the dump itself,
  both log helpers, and the host ctor. They regenerate to the same
  bytes from the same binary.
* `records.json` holds semantic records only (no per-instruction
  mnemonic list); regenerate with `gen_records.py`.
* `vtables.tsv` (105 rows), `callers.tsv`, `guards.tsv` are
  reproduced from the binary by `census.py`. Vtable slot values come
  from `.rela.dyn` entries: the file bytes of `.data.rel.ro` are
  ZERO, so the real values live only in the relocation addends (and
  in `__cxa_pure_virtual` R_X86_64_64 entries for the base Cache's
  pure `Name`). Vtable bases were confirmed by typeinfo name
  (`N7rocksdb9EnvLoggerE`, `N7rocksdb14AutoRollLoggerE`,
  `N7rocksdb22BlockBasedTableFactoryE`,
  `N7rocksdb33CompactOnDeletionCollectorFactoryE`).
* Source basis: RocksDB v8.1.1 headers (`env.h`,
  `configurable.h`, `customizable.h`, `table_properties.h`,
  `options.cc`, `column_family.cc`) for declaration order and
  call-site source. Selected names are corroborated by the target bodies
  described above; position-only assignments appear under Open unknowns.

## Verification

`python3 research/work-items/RE-001-dump-slot-method-names-115/verify.py`
prints ALL CHECKS PASSED: digest, MANIFEST, records/census/excerpt
regeneration, fixed samples + 3 seeded random gate spots byte-for-byte
vs fresh objdump and the raw binary, FDE ranges, excerpt content
pins, model constants, and the 35 model tests
(`python3 -m unittest tests.test_dump_slot_method_names_115`).

Model: `tools/dump_slot_method_names_115.py` -- EnvLogger helper routing by
level, AutoRollLogger opaque slot-4 forwarding, GetPrintableOptions/Name/ToString dispatch by concrete class,
the two devirtualization guards, the host gate, Logger Close
idempotence, and the GetOption "id" special case.

## Open unknowns

See `records.json` `open_unknowns`. In short: Logger vtable slots
11+ (their qwords do not continue the v8.1.1 Logger interface --
slots 11/13/14 have no relocation and read as zero, slot 12 points
at data 0x64cd8d0, the EnvLogger tail holds the shared Configurable
GetOption/AreEquivalent at offsets 0x78/0x80); AutoRollLogger's
slots 3/4/6/7/9/10 and Logger slots 4/6/7/10 named by header position
plus shape only, with downstream header emission unresolved;
TableFactory slots 3/5/6/7/10 by declaration order
only; the `BlockTableOptions` string at 0x444587 used at host
0x5d961f4; the two host callers' C++ names; the verification C++
enum names carried from #4311; the ColumnFamilyOptions padding-byte
names carried from #4286. Also: the binary's `column_family.cc`
line numbers differ from the v8.1.1 tag (610/619/624 in the binary
vs ~1162-1189 in the tag) -- statements, order, gate and Dump call
all match; only the line numbers differ.

## Environment

This VM has no cargo/rustc, no git-lfs, no Ghidra/Java, so `make
verify`, `make test` and `make catalogue-check` cannot run here. The
packet's own `verify.py` and the model tests run instead (see
Verification above).
