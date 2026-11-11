# RE-012: node115 statx capability probe, metadata projection and stat64 fallback

Component: foundation; task RE-012. Sole target Linux x86-64 node #115,
105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`. Original ELF VAs,
no rebasing, normalized bytes, captured execution or instruction emulation.
New project-authored static research and scripts are MIT.

## New question and outcome

When does the actual metadata boundary use statx versus stat64, which result
and error survives its capability probe, and how are statx fields converted
into the caller's 176-byte metadata representation?

The existing configuration, factory and recursive-directory packets retain
`0x5c9c810` as metadata context and inspect its mode, but do not close its
791-byte statx helper, capability cache, null-argument probe or complete field
projection. This outcome closes that bounded family, including the real long
path callback. Shared path-conversion context is not presented as new CString
reconstruction or byte credit. Live open PR titles inspected on 2026-11-04
showed no competing metadata capability/projection outcome; no issue was
opened, drafted or claimed.

## Actual entry and the fallback sentinel

Entry `0x5c9c810..0x5c9ca28` takes output in RDI and raw path pointer/length
in RSI/RDX. After short-path NUL preparation it calls
`0x5c9f780..0x5c9fa97` with directory argument **-100**, flags **0** and the
C-string path. The helper requests mask **0xfff**. These are observed numbers;
the directory argument has the usual Linux current-working-directory
interpretation. No actual directory or kernel state was queried.

Only helper result **tag 3** reaches the fallback call. Any other result is
forwarded as the whole 176-byte representation, including tag 1 for statx
success and tag 2 for error. On tag 3, the entry clears a 144-byte local
buffer and calls imported stat64. A result other than -1 copies those 144
bytes to output+0x20 and stores qword tag 0. A -1 result reads errno and
stores tag 2 with `(u32 errno << 32) | 2` at output+8. A statx operation error
therefore does **not** automatically trigger stat64.

The longer-path adapter `0x5c78cd0..0x5c78d82` invokes concrete callback
`0x5cad670..0x5cad748`. That callback makes the same helper call with -100
and flags 0, checks the same tag 3 and performs the same stat64 payload copy
and result tagging. Its owned C-string conversion, clearing and release stay
an explicit lower-level dependency; they are not reimplemented with a mock.
Interior NUL gives static error `0x64c2fb8` as tag 2 without a metadata call.

## Optional symbol and the actual capability policy

The statx helper reads the byte at **0x6500088**. A value of 2 immediately
writes tag 3 and returns, without a statx attempt. Other values proceed.
This packet does not read its live process value or infer current support
from captured slot/file bytes.

The dynamic symbol at slot **0x64ec9a0 is weak `statx`**, checked from the
symbol binding as well as its name and relocation. If the loaded slot is
nonzero, the operation calls:

```
statx(dirfd, path, flags, 0xfff, &raw256)
```

Otherwise it calls the actual imported variadic syscall function at
`0x64e06b8`, with syscall number **332** and the same arguments. A 256-byte
raw local buffer is zeroed before either call. This is a concrete fallback
from an absent libc symbol, not an assumption that the retained capture
carries a working libc entry.

On an operation result other than -1, initial cache value zero is changed to
one; an initially nonzero value is not changed on that success path. The
helper then projects the fields described below and returns tag 1.

On -1, the original errno word is saved **before** any probe. The cache is
read **again**. If it now equals 1, the helper returns tag 2 and the original
error directly. Otherwise it performs an additional capability probe:

* With the weak symbol present: `statx(0, NULL, 0, 0xfff, NULL)`.
* Without it: `syscall(332, 0, NULL, 0, 0xfff, NULL)`.

If that probe returns -1, its current errno is encoded and disposed. **Only
probe error integer 14** causes a store of cache value 1 and return of the
**original operation's error**. Every other probe outcome, including a
non--1 result, stores cache value 2, writes fallback tag 3 and disposes the
original operation error. The caller then enters stat64.

This policy is not simply “fallback only on ENOSYS.” The observed discriminator
is the deliberately invalid probe and integer 14. The result classifies
availability according to that code, not a proven OS version or universal
kernel capability. Cache reads/stores are retained byte operations; concurrent
mutation, initialization lifecycle and language-level synchronization remain
outside this packet. An invalid noncanonical cache value is not silently
identified with a supported-state enum.

## Complete observed statx field projection

The helper's output extent is 176 bytes. Offsets below are relative to the
raw 256-byte statx buffer and the output, respectively. Field labels use the
Linux ABI interpretation supported by the actual offsets; the byte transfers
and widths are the target observations.

| Output offset | Source or constant | Observed operation |
| --- | --- | --- |
| +0x00 | 1 | Qword tag |
| +0x08 | raw +0x50 | Copy 16 birth-timestamp bytes, including its raw reserved word |
| +0x18 | raw +0x00 | Copy mask dword |
| +0x1c | — | **Not written** |
| +0x20 | raw major +0x88, minor +0x8c | Pack device qword |
| +0x28 | raw +0x20 | Inode qword |
| +0x30 | raw +0x10 | Link-count dword, zero-extend to qword |
| +0x38 | raw +0x1c | Mode word, zero-extend to dword |
| +0x3c | raw +0x14 | UID/GID pair, eight bytes |
| +0x44 | 0 | Dword |
| +0x48 | raw major +0x80, minor +0x84 | Pack device qword |
| +0x50 | raw +0x28 | Size qword |
| +0x58 | raw +0x04 | Block-size dword, zero-extend to qword |
| +0x60 | raw +0x30 | Block-count qword |
| +0x68 / +0x70 | raw +0x40 / +0x48 | Access seconds qword / nanoseconds dword zero-extended to qword |
| +0x78 / +0x80 | raw +0x70 / +0x78 | Modification seconds / nanoseconds, same widths |
| +0x88 / +0x90 | raw +0x60 / +0x68 | Change seconds / nanoseconds, same widths |
| +0x98..+0xb0 | 0 | 24 bytes |

The supplied statx mask is forwarded; this packet does not assert that any
particular optional timestamp was supplied by a real kernel. It does not
normalize the raw reserved bytes or output padding to zero.

For each major/minor u32 pair, device packing maps major bits 0..11 to output
8..19, major bits 12..31 to output 44..63, minor bits 0..7 to output 0..7 and
minor bits 8..31 to output 20..43. Those disjoint bit ranges cover the qword.
The actual source masks are `0xfff00`, `0xfffff000` and sign-extended
`0xfff00000`. `verify.py` checks their arithmetic consequences against an
independent per-bit placement at 1156 zero/all-one/one-hot pairs. This is
static bit algebra, not a captured instruction interpreter or runtime oracle.

`projection.json` records the entire field map and its intentionally
**unwritten** intervals. Legacy tag 0 leaves output+8..+0x20 unwritten; error
tag 2 writes only the tag and error word; the internal fallback tag 3 writes
only the tag. Forwarding 176 bytes is a layout observation, not permission to
claim those untouched bytes have deterministic values or to count them as
matched reconstruction bytes.

## Evidence and qualification

Five complete FDEs total **1927 bytes / 475 instructions**: metadata entry,
statx capability/projection helper, long-path adapter and callback, and error
disposal context. They contain 31 calls and 54 branch records. Export sizes
are not reconstructed byte counts. `records.json` binds full body hashes,
actual FDE/CIE bytes, LSDA addresses, helper/data relocation writers and the
five symbols `statx`, `syscall`, `stat64`, `__errno_location`, `memcpy`.

GNU objdump, LLVM objdump and Capstone agree on every instruction byte; GNU
readelf independently confirms all extents. Only a separate LLVM LOCK prefix
row, if present, is joined to its contiguous instruction. No byte is masked.
`tools.json` retains versions and `collect.py` retains actual options.

```sh
python3 -B research/work-items/RE-012-metadata-fallback-115/collect.py --out work/fresh-metadata-export
diff -u research/work-items/RE-012-metadata-fallback-115/records.json work/fresh-metadata-export/records.json
python3 -B research/work-items/RE-012-metadata-fallback-115/verify.py --out work/fresh-metadata-check.json
```

The verifier freshly reproduced the record and rejected **34 actual instruction
corruptions, one static error-record corruption, four RELATIVE-addend
mutations, five imported-writer mutations and two wrong/truncated capture
controls**. Narrow checks do not depend on the whole-file hash to detect their
operand/data/relocation changes. It also checks the device masks and 1156
bit-placement pairs. `qualification.json` records actual outcomes; parent
publication owns repository/catalogue verification.

## Boundaries

No captured process, instruction evaluator, metadata syscall, filesystem
operation or network was run. No Rust implementation, mock kernel, peer
runtime, hosted CI or container result is claimed. The complete CString
implementation, allocator/error-disposal side effects, imported interposition,
cache concurrency, OS structures outside these observed transfers, native
padding, pointer validity and unwind behavior remain boundaries. This is a
concrete capability/result-layout closure, not full filesystem or component
equivalence. All 92 component gates and byte-comparison totals remain unchanged.
