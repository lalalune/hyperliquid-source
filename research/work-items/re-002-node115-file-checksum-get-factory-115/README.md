# RE-002: node #115 GetFileChecksumGenCrc32cFactory singleton getter

This packet reconstructs one bounded node #115 behavior: the
`rocksdb::GetFileChecksumGenCrc32cFactory` singleton getter at
`0x61cd600` (FDE `0x61cd600..0x61cd716`), as attributed by the vendor
census (`research/work-items/RE-002-node115-vendor-census/census.json`,
whose `target_body_sha256` matches the body hash in `result.json`;
also recorded in `research/byte-windows.json`). It hands out the
process-wide shared `FileChecksumGenCrc32cFactory` whose
`CreateFileChecksumGenerator` method (slot 19, `0x61cd2e0`) and
`Finalize`/`Update` siblings were reconstructed in the companion
packets; the factory vtable itself was reconstructed in the merged
packet
`research/work-items/RE-002-node115-rocksdb-checksum-factory-vtable/`,
which records this function only as the `lea` store site in
`stores.tsv` — this packet reconstructs the getter's behavior.

- Target release and full SHA-256: Linux x86-64 node #115,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Claim status: instruction bytes, window hashes, the guard test, the
  init stores, the copy path and the increment selection are
  observations. The C++ symbol attribution comes from the vendor
  census. The object-field names (`use_count`, `weak_count`, the
  vector-like member) and the thread-flag byte's identity are
  inferences from the disassembly. The element identity, the release
  helper and the callers are open unknowns (see below).
- Scope included: the getter body, the guard, the init path, the copy
  path, the factory object layout read off its destructor, and the
  control-block vtable read off the relocations. Excluded: callers of
  the getter, and the shared release helper at `0x5d35070` (not
  decoded).

## Reproduce

From the repository root, with the materialized work binary at
`work/hl-node-115.bin`:

```sh
python3 tools/file_checksum_get_factory115.py --verify
python3 tools/file_checksum_get_factory115.py --out research/work-items/re-002-node115-file-checksum-get-factory-115
python3 -m unittest tests.test_file_checksum_get_factory115
(cd research/work-items/re-002-node115-file-checksum-get-factory-115 && sha256sum -c MANIFEST.sha256)
```

Generation and tests were run on Linux x86-64 with CPython 3.12. GNU
objdump was used only for bounded human inspection; its text is not parsed
or included in generated evidence. The node binary was not executed. No
cargo/rustc/git-lfs/Ghidra is available on this machine, so no native
rebuild or Ghidra cross-check was performed.

## Evidence

### Contract

`get() -> shared_ptr<FileChecksumGenCrc32cFactory>`, observed
register use: `rdi` = hidden out-pointer, returns `rdi`. The
function copies the 16-byte static shared_ptr to `[rdi]`.

### Guard and init (observed)

| Step | Range | Content |
| --- | --- | --- |
| guard test | `0x61cd600..0x61cd629` | load the guard byte at `0x6508930`; nonzero jumps to the copy path; zero calls `__cxa_guard_acquire` (PLT `0x63f0fc0`), whose zero return also goes to the copy path |
| factory alloc | `0x61cd670..0x61cd6ae` | `operator new(0x20)` (PLT `0x63f0dd0`); zero the whole object; store vptr `0x64d79b0` (lea `0x64d79a0` + `0x10`); store the object at the static pointer `0x6508940`; `operator new(0x18)` for the control block |
| control setup | `0x61cd6ae..0x61cd6fe` | store control vptr `0x64d7a90` (lea `0x64d7a80` + `0x10`); store the counts word `0x0000000100000001` from `.rodata` `0x459b20` (use 1, weak 1); store the factory object at control+`0x10`; store the control block at the static pointer `0x6508948`; `__cxa_atexit` (PLT `0x63f0f80`) registers the destructor `0x61cd720` with dso handle `0x64efa20`; `__cxa_guard_release` (PLT `0x63f0fd0`); jump to the copy path |
| landing pads | `0x61cd6fe..0x61cd716` | `0x61cd6fe` jumps to `0x61cd5d1` (`__cxa_guard_abort`, then `_Unwind_Resume`); `0x61cd70a` jumps to `0x61cd5e1` (`__cxa_begin_catch`, delete the factory object via `0x61cd400`, `__cxa_rethrow`) |

### Copy path (observed)

| Window | Range | Content |
| --- | --- | --- |
| copy_path | `0x61cd629..0x61cd658` | `movdqa` the 16-byte static, `movups` it to the out-pointer; when the control pointer is zero, return without incrementing; otherwise load the `.got` pointer at `0x64ed290`, test its byte, and take the plain `addl $0x1, 0x8(%rax)` when nonzero |
| copy_lock | `0x61cd658..0x61cd66d` | padding, then `lock addl $0x1, 0x8(%rax)` when the thread-flag byte is 0, and return |

The `.got` slot at `0x64ed290` is zero in the static image
(runtime-filled); the byte it points to selects the increment form,
consistent with `__libc_single_threaded` (1 = single-threaded), which
is an inference, not a proven identity.

### Object layouts (observed)

Factory object, `0x20` bytes (the deleting destructor at `0x61cd400`
frees it with size `0x20`):

| Offset | Field | Evidence |
| --- | --- | --- |
| `+0x0` | vptr | `0x64d79b0`, the FileChecksumGenCrc32cFactory vtable address point |
| `+0x8` | vector-like member, begin | zeroed by init; the destructor walks `[begin, end)` |
| `+0x10` | vector-like member, end | the destructor compares the cursor against it |
| `+0x18` | vector-like member, capacity | the destructor frees the array with size `end - begin` |

Each member element is `0x30` bytes and starts with a std::string
(pointer `+0x0`, length `+0x8`, SSO buffer / allocated capacity
`+0x10`): the destructor frees `[element+0]` with size
`[element+0x10]+1` unless `[element+0]` equals `element+0x10`,
the exact `_M_dispose` shape confirmed by the identical codegen in
the generator destructor at `0x61cd490`.

Control block, `0x18` bytes:

| Offset | Field | Evidence |
| --- | --- | --- |
| `+0x0` | vptr | `0x64d7a90`; slot 0 bare return, slot 1 `operator delete(0x18)`, slot 2 dispose (deletes the factory via `0x61cd400`), slot 3 `operator delete(0x18)`, slot 4 returns null |
| `+0x8` | counts word | `0x0000000100000001`: use_count 1 (low dword), weak_count 1 (high dword) |
| `+0x10` | managed pointer | the factory object |

### Release (observed, supporting evidence only)

The atexit destructor at `0x61cd720`: when the counts word is
exactly `0x0000000100000001` it zeroes the counts, calls slot 2
(dispose) and tail-calls slot 3 (destroy); otherwise it decrements
use_count (`lock xadd` when the thread-flag byte is 0, plain
decrement otherwise) and, when the old value was 1, tail-calls the
shared release helper at `0x5d35070`.

## Unknowns

- Factory member element identity: each `0x30`-byte element starts
  with a std::string; the trailing `0x10` bytes of the element and
  what the member holds in practice are not determined from this
  packet.
- Thread-flag byte identity: the `.got` slot at `0x64ed290` is zero
  in the static image and filled at load; the byte it points to
  selects the atomic vs plain increment, consistent with
  `__libc_single_threaded`, but the target was not resolved from the
  binary.
- Shared release helper at `0x5d35070`: the destructor tail-calls it
  when the last use drops; its body was not decoded in this packet.
- Callers of `GetFileChecksumGenCrc32cFactory`: no caller census was
  run for this packet.
