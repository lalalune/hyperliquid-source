# RE-002 · Node #115 RocksDB WritableFileWriter::GetFileChecksum

Component: storage / file writer / checksum. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does a `WritableFileWriter` report the checksum of the file it wrote -- what does
`rocksdb::WritableFileWriter::GetFileChecksum()` return with and without a checksum
generator set, and who reads it? The single FDE is census-bound (body hash matches the
vendor census `target_body_sha256` exactly; source hash reproduced by zeroing the one
kind-4 relocation at offset 102):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::WritableFileWriter::GetFileChecksum` | 0x604c710..0x604c77a | 106 | `2c4cb495674d79320e55e2b6908d84b6ac2e82fb4f2b5da278017d2975ed174f` |

The full hashes are in `functions.tsv` and `records.json`.

## Answer (pinned)

**Signature.** `std::string GetFileChecksum()`; hidden sret out in `rdi`, `this` in `rsi`.
Stack frame: `push rbx`, `sub rsp, 0x10`; stack canary stored at `rsp+0x8` and checked
before every return; a bad canary calls `__stack_chk_fail`. No LSDA, no `.cold` FDE.
The `.eh_frame` record at section offset `0x367130` has length `0x20`, range `0x6a`,
`aug_len` 0: no LSDA pointer, no landing pad.

**Dispatch.** Load `this+0xc8` (`checksum_generator_`, a `std::unique_ptr<FileChecksumGenerator>`
per `file/writable_file_writer.h:163`); if null, build the empty SSO string in the sret out
(`ptr = out+0x10`, `size 0`, first byte NUL) -- that is `kUnknownFileChecksum`, `constexpr char [] = ""`
(`include/rocksdb/file_checksum.h:27`) -- then jump back to the canary check and return;
else call vtable slot 4 of the generator with (`out`, `generator`). Slot 4 is `GetChecksum`:
`FileChecksumGenerator`'s virtuals occupy six vtable entries in declaration order -- the two
Itanium ABI destructor slots (complete-object dtor, deleting dtor), then `Update`, `Finalize`,
`GetChecksum`, `Name` (`include/rocksdb/file_checksum.h:52-67`) -- so the fifth entry (`0x20`
past the vptr) is `GetChecksum() const`, returning `std::string` by value into the same sret out.
The 26 instructions (verified verbatim by `--live`):

```
endbr64
push   rbx
mov    rbx, rdi                  # save sret out
sub    rsp, 0x10
mov    rsi, [rsi+0xc8]           # checksum_generator_
mov    rax, fs:[0x28]            # canary
mov    [rsp+8], rax
xor    eax, eax
test   rsi, rsi
je     0x604c760                 # null: build empty string
mov    rax, [rsi]                # vptr
call   [rax+0x20]                # GetChecksum (vtable slot 4)
mov    rax, [rsp+8]              # canary check
sub    rax, fs:[0x28]
jne    0x604c775                 # bad canary: __stack_chk_fail
add    rsp, 0x10
mov    rax, rbx
pop    rbx
ret
nop                              # 7-byte alignment padding inside the FDE
lea    rax, [rdi+0x10]           # null branch: empty SSO string
mov    [rdi+8], 0
mov    [rdi], rax
mov    byte [rdi+0x10], 0
jmp    0x604c73e                 # back to the canary check
call   0x63f0d70                 # __stack_chk_fail@plt
```

The canary is checked on both paths, after the virtual call on the present path and after the
empty-string build on the null path, so a bad canary fails even with no generator set. A throw
from the generator's `GetChecksum` propagates with no cleanup (no LSDA, no landing pad) and the
canary check never runs on that path -- the throw beats the canary check. The
`assert(checksum_finalized_)` in the upstream source is compiled out: no reference to the flag
in the FDE, so the model does not gate on finalization. The concrete checksum bytes are the
generator's own behavior (already reconstructed for the CRC32C/XXH generators in earlier RE-002
packets), not this function's; this model pins the dispatch, the null branch and the returned
value only.

**Callers.** Exactly 6 direct calls, 0 tail jumps, 0 LEA refs (whole-`.text` E8/E9/LEA scan,
Capstone-validated) -- `rocksdb::BuildTable` (site 0x5e1f4df, stores the result in
`meta->file_checksum`), `CompactionOutputs::WriterSyncClose` (site 0x5e1892e),
`BlobLogWriter::AppendFooter` (site 0x5e2734f), and the three table builders' own
`GetFileChecksum` wrappers, which delegate to this function -- `BlockBasedTableBuilder`
(site 0x60e3f6a), `CuckooTableBuilder` (site 0x615cef5), `PlainTableBuilder` (site 0x618b378).

**Upstream cross-check.** RocksDB v8.1.1 (`meta/rocksdb`, read live this cycle) defines this helper
exactly as the binary behaves -- `file/writable_file_writer.cc:415-422` (`if (checksum_generator_
!= nullptr) return checksum_generator_->GetChecksum(); else return kUnknownFileChecksum`) --
and `db/builder.cc:335-336` stores the result in `meta->file_checksum` and calls
`GetFileChecksumFuncName` next: the same `BuildTable` call site the census finds in the binary.
`include/rocksdb/file_checksum.h:27-28` defines `kUnknownFileChecksum` as `""` and
`kUnknownFileChecksumFuncName` as `"Unknown"` (the latter is the null-branch literal of the
sibling `GetFileChecksumFuncName` at 0x604c780, verified at `0x974e00` in the binary).

## Cases

300 deterministic cases (`cases.tsv`, generated by `tools/get_file_checksum115.py`):

- 100 checks: 50 checksum variants (10 lens x 5 patterns: repeated char, hex, arithmetic bytes,
  `crc32c:`-prefixed, NUL/0xff) x 2 generator states (null, `FileChecksumGenCrc32c`).
- 100 edge: 10 checksum values x 2 generator states x 5 conditions (canary ok, canary bad,
  generator throws, throw with bad canary, generator returns empty), pinning that the canary is
  checked on the null path too, that a throw beats the canary check, and that `gen_throws` is
  vacuous with no generator.
- 100 bindings: 25 (generator, checksum) pairs x 4 recorded invariants (`body_sha256`,
  `source_sha256`, `fde_record`, `caller_census`) — each row records the invariant's expected
  value and replay compares it.

0 mismatches on replay (`--verify-cases`). 12 tests pass
(`tests/test_get_file_checksum115.py`). Live check (`--live`, 16 legs) passes:
artifact digest, body hash, source hash (1 kind-4 relocation), the FDE record
(length `0x20`, range `0x6a`, `aug_len` 0, no LSDA), the 26 verbatim instructions,
2 calls (1 indirect vtable, 1 `__stack_chk_fail`), 1 ret, 1 jmp, both conditional jumps
internal, the 6-site caller census, and the model end-to-end legs (null/present x
empty/binary, canary, throw order).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never executed. The tool models
the helper in Python from its whole-FDE disassembly; checksum strings are deterministic values
(the generator's `GetChecksum` may return arbitrary bytes, including non-printable ones, per the
header comment), not real file bytes. `make verify/test/catalogue-check` in a tooled environment
is still owed upstream.
