# RE-001: pin node #115 the EncryptedFileSystemImpl factory 0x5ff6690 and the FileSystemWrapper ctor 0x5fe7210

## Question

Which host registers an option group against the provider map 0x6505300
(one entry, "provider"), what does it build, and what is the construction
chain behind it? Resolves the open unknown left by #4395: the only
non-initializer lea reference to the provider map is 0x5ff6763 inside
FDE 0x5ff6690..0x5ff682e.

## Answer (one paragraph)

The host 0x5ff6690 is the EncryptedFileSystemImpl factory: it builds a
0x40-byte `rocksdb::(anonymous namespace)::EncryptedFileSystemImpl`
(vtable 0x64cfca0), wraps the caller-supplied FileSystem shared_ptr
(2nd arg) via the FileSystemWrapper ctor 0x5fe7210, stores the
caller-supplied BlockCipher shared_ptr (3rd arg) at +0x30/+0x38, and
registers the group "EncryptionProvider" with the provider map 0x6505300
(one entry, "provider", type 22, verification 1, flags 0x400, offset 0),
so the cipher is configured through the "provider" option. The wrapper
ctor also registers the empty-named group with the map 0x65051e0 (one
entry, "target", type 22, verification 1, flags 0x2400, offset 0), so
the wrapped FileSystem is configured through the "target" option. The
registered factory 0x5fe7a20 calls the factory with two empty
shared_ptrs, so the registered "EncryptedFileSystem" starts blank and is
configured later through those two options.

## Evidence

- `records.json` -- semantic records only (no per-instruction mnemonic
  list): the factory, the wrapper ctor, the FileSystem ctor, the
  group dtor, both dtors, the registered factory, the Name() slot, the
  record ctor, the static initializer, the registry builder, the
  manager, the two maps, the four vtables, cited context, open unknowns.
- `fn-*.objdump.txt` -- whole-function objdump excerpts (repo-relative
  binary path) for the factory, the wrapper ctor, the FileSystem ctor,
  the group dtor, both dtors, the registered factory, Name(), the
  record ctor, the static initializer, the registry builder, and the
  std::function manager.
- `callers.tsv` -- every lea reference to the two maps, the vtables and
  the factories, and every E8 call site in the packet, with the
  enclosing FDE.
- `maps.tsv` -- the provider map (one entry "provider") and the target
  map (one entry "target"), with pack/flags/offset.
- `vtables.tsv` -- all 62 slots of the three FileSystem vtables
  (EncryptedFileSystemImpl, FileSystemWrapper, FileSystem) plus the 14
  slots of the Configurable vtable, each with its typeinfo name
  resolved from .rela.dyn.
- `literals.tsv` -- the string/immediate literals behind the claims.
- `frames.txt` -- the FDE extents for every pinned window.
- `census.py`, `export_excerpts.py`, `gen_records.py` -- the generators
  for the tables, excerpts, and records above.
- `verify.py` -- self-checks; run it from the repo root:
  `python3 research/work-items/RE-001-encrypted-fs-factory-115/verify.py`
  (artifact digest, manifest, excerpt regeneration byte-identical to
  fresh objdump, FDE identities, raw-binary spot bytes, literals, lea
  census, semantic-only records, model tests). ALL CHECKS PASSED.

## Model and tests

- `tools/encrypted_fs_factory_115.py` -- `create_encrypted_fs`,
  `create_registered_encrypted_fs`, `EncryptedFileSystemImpl`,
  `FileSystemWrapper`, `SharedPtr`, `ControlBlock`, `OptionRecord`,
  `build_target_record`, `build_provider_record`, `manager_op`,
  `OutSlot`, `REGISTRY`, `MAP_ENTRIES`.
- `tests/test_encrypted_fs_factory_115.py` -- 20 tests, all passing.

## Open unknowns

- The exact C++ type of the factory's out slot (raw double pointer vs
  smart-pointer out param) -- open.
- The registered factory's rdi/rsi roles: neither is read, so whether
  rdi is the spec string and rsi an options object is open.
- The paired second functions' full roles: the manager 0x5fe5700
  handles ops 0/1 only; clone/destroy handling for the captureless
  lambda lives elsewhere -- open.
- Why the registered factory creates a blank impl (null wrapped
  FileSystem, null cipher) instead of parsing its spec -- open;
  configuration is presumed to follow through the "target"/"provider"
  options.
- The FileSystem vtable slots 19..61 (impl overrides at 21..26 and
  others) -- C++ names open.
- The impl slot-16 override 0x5ff0990, slot-5 override 0x5fe7d00 and
  slot-12 override 0x5fe6910 -- bodies not pinned here.
- The empty map 0x6505220's purpose -- zeroed with an atexit dtor but
  no inserts binary-wide.
- The small host 0x5ffabd0's full dispatch (the non-"ROT13" path via
  0x60bb890 / 0x5ffa710) -- still open from #4395.
