# RE-002: node #115 FileChecksumGenCrc32c Name

This packet reconstructs one bounded node #115 behavior: the
`rocksdb::FileChecksumGenCrc32c::Name` method at `0x61cd020` (FDE
`0x61cd020..0x61cd02c`), vtable slot 5 of `FileChecksumGenCrc32c`
(address point `0x64d7970`; the vtable itself was reconstructed in
the merged packet
`research/work-items/RE-002-node115-rocksdb-checksum-vtable/`).

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, the `lea` target and the FDE are
  observations. The C++ symbol attribution rests on the vtable slot,
  the `lea` target string and the factory corroboration below — there
  is no vendor-census attribution for this address, stated as an
  unknown in `records.json`.
- Scope included: the Name body, the string it returns, and the
  sibling methods that use that same name. Excluded: callers of Name,
  and any claim about which files the node checksums with this
  generator.

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
objdump -d --start-address=0x61cd020 --stop-address=0x61cd02c work/hl-node-115.bin
(cd research/work-items/re-002-node115-file-checksum-name-115 && sha256sum -c MANIFEST.sha256)
```

The node binary was not executed. No cargo/rustc/git-lfs/Ghidra is
available on this machine, so no native rebuild or Ghidra cross-check
was performed.

## Evidence

### Contract

`name(this: *const FileChecksumGenCrc32c) -> *const c_char`. Observed
register use: no arguments are read; `rax` returns the string
pointer. It returns the pointer to the generator name string.

### Name body (observed)

The whole function is 12 bytes (`file_checksum_name115.hex`,
`file_checksum_name115.objdump.txt`):

| Address | Bytes | Instruction |
| --- | --- | --- |
| `0x61cd020` | `f3 0f 1e fa` | `endbr64` |
| `0x61cd024` | `48 8d 05 43 63 26 fa` | `lea -0x5d99cbd(%rip),%rax` — resolves to `0x43336e` |
| `0x61cd02b` | `c3` | `ret` |

The 19 bytes at `0x43336e` in `.rodata` are `FileChecksumCrc32c`
followed by a NUL byte.

### Uniqueness (observed)

A scan of the whole `.text` section for `lea` instructions resolving
to `0x43336e` finds exactly one site, `0x61cd024` inside this
function. No other function returns this string pointer.

### Corroboration (observed)

The factory `CreateFileChecksumGenerator` at `0x61cd2e0` (PR #5419)
creates a generator exactly when the context name is the 18-byte
string `FileChecksumCrc32c` (length `0x12` plus a byte compare
against the same bytes). The name this function returns is the name
the factory gates creation on.

### Sibling slots (inferences, not modelled here)

- Slot 2, Update (`0x61cd1a0`): `crc_` is the raw CRC32C extend
  accumulator (PR #5387).
- Slot 3, Finalize (`0x61cd1c0`, PR #5416): appends the big-endian
  form of the accumulated CRC32C word to the string at `+0x10`.
- Slot 4, GetChecksum (`0x61cd510`, PR #5424): returns a copy of the
  string at `+0x10`.

## Check values

- `name() = 0x43336e`, pointing at `b"FileChecksumCrc32c\x00"` in
  `.rodata`.
- Body SHA-256 `28e4bd5956be83a62e244e6c40d9585e72f1a0079cb3b8e18fb9b80416014542`
  over the 12 bytes `f30f1efa488d05436326fac3`.
