# RE-001: node #115 rocksdb::ConfigOptions default ctor

Task: RE-001. Bounded question: what are the defaults of
`rocksdb::ConfigOptions`, how is one torn down, and where is the default
ctor used on node #115?

## What this pins

`rocksdb::ConfigOptions::ConfigOptions()` (`_ZN7rocksdb13ConfigOptionsC1Ev`,
`0x60bb890..0x60bb932`, 162 B) builds an 80-byte object:

| offset | field | default | notes |
|---|---|---|---|
| +0x00 | flag bytes 0-3 | `00 01 01 01` | C++ names open |
| +0x04 | flag byte 4 | `0x00` | SetOptions sets it to 1 |
| +0x08 | delimiter `std::string` | `";"` (SSO, len 1) | Persist replaces it with `"\n  "`; AsString re-assigns `";"` (no-op) |
| +0x28 | u32 | 0 | C++ name open |
| +0x2c | u8 | `0xff` | C++ name open |
| +0x30 | u64 | `0x80000` (524288) | C++ name open; Persist overwrites it with DBOptions+0x220 when non-null |
| +0x38 | `Env*` | `Env::Default()` | raw pointer; stored twice by the ctor (same value), never released by the dtor |
| +0x40 | `shared_ptr<ObjectRegistry>` | `NewInstance()` child of Default | released by the dtor via `_M_release` on +0x48 |

The dtor `ConfigOptions::~ConfigOptions()` (`_ZN7rocksdb13ConfigOptionsD1Ev`,
`0x5e33fb0..0x5e33fea`, 58 B) releases the registry shared_ptr and disposes
the delimiter string, in that order. It is called from landing pads only:
all 44 direct call sites sit inside small landing-pad FDEs, and all nine
construction hosts inline the teardown (release +0x48, dispose +0x08) on
their normal path.

`ObjectRegistry::NewInstance()` (`0x61f9400..0x61f963e`) is the ctor's sole
callee of interest and the ctor is its sole caller binary-wide. It allocates
a fresh 0xd0-byte control block (vtable `0x64d8f00`, counts `0x100000001`
from `0x459b20`), builds a fresh 0xc0-byte registry whose parent
(`+0x60`) is the Default singleton, and zeroes registry `+0x70..+0xb7`
(including the mutex slot at `+0x98`). This resolves #4015's open unknown
about that region and corrects #4015's label: the routine is `NewInstance`,
not `clone`. It also answers #4015's other open unknown: the clone-caller
function `0x60bb890` is this ctor.

The nine construction sites (call site, host, overrides, consumer) are
listed in `callers.tsv` and modelled in `tools/configoptions_default_ctor_115.py`:

1. `0x5d8eacf` `ColumnFamilyData::SetOptions` — sets +0x04=1; consumer is
   the apply helper `0x60c4550` (no catalogue label; copies CFOptions,
   builds the Configurable view, runs `ConfigureFromMap`).
2. `0x5e3406f` `CompactionServiceResult::Write` — sets +0x03=0; consumer
   `OptionTypeInfo::SerializeType 0x60bbe50`.
3. `0x5e34458` `CompactionServiceResult::Read` (version-1 arm) — sets
   +0x00=1, +0x03=0; consumer `OptionTypeInfo::ParseType 0x60c1bb0`.
4. `0x5ffad84` `CTREncryptionProvider::AddCipher` — pure defaults;
   consumer is the cipher factory `0x5ffa710` (pinned by #4028).
5. `0x60a1dcf` `GetMutableDBOptionsFromStrings` — pure defaults; consumer
   `OptionTypeInfo::ParseType 0x60c18b0`.
6. `0x60a20cd` `MutableDBOptionsAreEqual` — pure defaults; consumer
   `OptionTypeInfo::StructsAreEqual 0x60bfda0`.
7. `0x60d4a48` `PersistRocksDBOptions` (outer) — delimiter `"\n  "`,
   +0x03=0, +0x30=DBOptions+0x220 when non-null; consumer is the inner
   `PersistRocksDBOptions 0x60d2820`, whose prologue re-copies the
   ConfigOptions field-by-field (see `persist-copy-60d2820.objdump.txt`).
8. `0x612073b` `BlockBasedTable::Open` — gated: constructs only when a
   stored prefix-extractor name exists and no transform is instantiated;
   consumer is the SliceTransform create host `0x61ca3d0` (pinned by #3764).
9. `0x61c83aa` `SliceTransform::AsString` — re-assigns delimiter `";"`;
   consumer `Configurable::ToString 0x60971c0`.

## Evidence

- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (`provenance/artifacts.json`).
- Raw disassembly: one verbatim `objdump -d` excerpt per window, produced
  by `export_excerpts.py` from the relative path `work/hl-node-115.bin`
  (GNU objdump 2.42). The excerpts are whole-function except
  `persist-copy-60d2820.objdump.txt`, which is the bounded prologue
  `0x60d2820..0x60d290f` of the inner Persist (the field-by-field copy),
  labelled as such. Mnemonics such as `endbr64` are genuine instructions
  present in the target binary, not placeholders.
- `records.json` holds semantic records only (field map, sites, census,
  relocations, literals, corrections, open unknowns) — no per-instruction
  mnemonic list.
- `census.py` reproduces the caller census: 9 direct ctor calls, 44 direct
  dtor calls, 1 direct NewInstance call, 0 tail jumps, 0 qword hits.
- `frames.txt` lists the FDE header lines for every excerpted window.
- `relocations.txt` quotes the relocation entries for the control-block
  vtable slot, the AddCipher once slots and the use-count selector byte.
- `newinstance-61f9400.objdump.txt` is re-shipped byte-identical from
  #4015 (`clone-61f9400.objdump.txt`); see `records.json` corrections.

## Corrections to earlier PRs

- #4015 called `0x61f9400` "clone"; the catalogue name is
  `ObjectRegistry::NewInstance()`, creating a fresh child registry.
- #3950 described `0x5fe2860` as "the default holder initializer"; it is
  `rocksdb::Env::Default()` (the holder initialization lives inside it);
  it has 17 callers binary-wide.

## Open unknowns (not presented as facts)

- C++ names of the five flag bytes and of the +0x28/+0x2c/+0x30 scalars.
- Identity of DBOptions+0x220 (the value Persist copies into +0x30).
- C++ name of the SetOptions apply helper `0x60c4550`.
- Exact argument mapping of the SliceTransform create host `0x61ca3d0`
  at the BlockBasedTable::Open site.

## Verification

```
python3 research/work-items/RE-001-configoptions-default-ctor-115/verify.py
python3 tests/test_configoptions_default_ctor_115.py   # 132 tests
```

`verify.py` checks: the artifact digest against `provenance/artifacts.json`,
the manifest, excerpt regeneration against fresh objdump, fixed samples
plus 3 seeded random gate spots byte-for-byte against fresh objdump AND
the raw binary, the FDE ranges, the census reproduction, the model
constants, the relocation records and the data literals.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
`make verify test catalogue-check` could not be run here; the packet's
own `verify.py` and the Python model tests above were run instead. The
node #115 binary is materialized locally and all binds were checked
against it.
