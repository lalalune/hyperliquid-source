# RE-002: reconstruct node #115 `rocksdb::SequentialFileReader::NewReadaheadSequentialFile`

Task RE-002 (RocksDB checksum reconstruction), node #115. One bounded
behavior: the static factory that wraps a raw `FSSequentialFile` in
a `ReadaheadSequentialFile` when the requested readahead exceeds the
file's required buffer alignment -- and returns the file unchanged
otherwise:

  std::unique_ptr<FSSequentialFile> NewReadaheadSequentialFile(
      std::unique_ptr<FSSequentialFile>&& file, size_t readahead_size)

2,400 byte-checked cases; 28 tests, all pass.

## Target

Node #115 artifact `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`). Two FDEs, BOTH vendor-census-bound
(member `a895f7517936a0f7-sequence_file_reader.o`, librocksdb-sys
0.11.0+8.1.1), hashes recomputed from the binary, source hashes
reproduced exactly by zeroing the census relocations:

| function | range | size | body SHA-256 | source SHA-256 | relocations |
|---|---|---|---|---|---|
| `rocksdb::SequentialFileReader::NewReadaheadSequentialFile` | `0x6048c30..0x6048d67` | 311 B | `487104cbbb9fcb45015967a66b4a3b2556ec62c77b953f9df8b0e169bf74622a` | `2acc4f4d5002b829a0de56b514ecea5154cc15d0dc6553c6ffe4e00ef3280eff` | 6 (kinds 2/4) |
| `...::NewReadaheadSequentialFile.cold` | `0x6048bfe..0x6048c30` | 50 B | `204e9c9a73ea9c23ee6ac54e96f84939b5ae5c642fc96f40d46a3edbeb7de26a` | `017b892ebf9b19afe7eb0438854d2d4d626f37b6ae9396da9796b78f94b3da38` | 3 (kind 4) |

## Reconstruction (whole-FDE disassembly, Capstone-validated)

Signature: `std::unique_ptr<FSSequentialFile>
NewReadaheadSequentialFile(std::unique_ptr<FSSequentialFile>&& file,
size_t readahead_size)`; the hidden sret (the out unique_ptr) in
`rdi`, the input unique_ptr* in `rsi`, the readahead size in `rdx`.

**1. Gate (0x6048c47..0x6048c53).** `alignment =
file->GetRequiredBufferAlignment()` -- the virtual call through
vtable slot 5 (`call *0x28(%rax)` at 0x6048c4d). If `alignment >=
readahead_size` (unsigned `jb`), go to the move path (step 2).
Upstream `sequence_file_reader.cc:594`, with the short-circuit
comment ("return the original file if readahead_size is too small
and hence doesn't make sense to be used for prefetching").
Equality takes the move path.

**2. Move path (0x6048c55..0x6048c72).** `out->ptr = file.ptr`;
`file.ptr = nullptr` (the move); return `out`.

**3. Wrap path (0x6048c78..).** `operator new(0x80)` for the
`ReadaheadSequentialFile` object (PLT `_Znwm` 0x63f0dd0).

**4. vptr + file_ (0x6048c82..0x6048c9e).** The input file pointer
is moved out (`file.ptr = nullptr` at 0x6048c86) and stored at
`+0x8`; the vtable pointer at `+0x0` is the LEA at 0x6048c91 to
`0x64d1d80` -- the `ReadaheadSequentialFile` vtable, proven by its
`.rela.dyn` entries (see the vtable table below).

**5. Second alignment call (0x6048c9b..0x6048ca2).** `alignment =
file_->GetRequiredBufferAlignment()` AGAIN -- the constructor
init-list call (`sequence_file_reader.cc:303`); the binary does NOT
reuse the gate result. `alignment_` (`+0x10`) is set from this
second call. A file whose two calls disagree takes the gate from
call 1 and the layout from call 2; the model records both.

**6. Roundup (0x6048ca5..0x6048ced).** `readahead_size_` (`+0x18`)
= `Roundup(readahead_size, alignment_)` -- `((x + y - 1) / y) * y`
via `div` (`util/aligned_buffer.h:62`), i.e. `(x + y - 1) -
(x + y - 1) % y`. If `alignment_` is 0 here the div faults (`#DE`,
exactly `Roundup(x, 0)`); the model raises `ZeroDivisionError`
for that case. It can only happen when `readahead_size > 0` and
the file reports alignment 0 (the gate `0 < readahead_size`
already passed).

**7. AlignedBuffer init (0x6048cb6..0x6048ce9).** `lock_` (`+0x20`,
`std::mutex`, 40 bytes) zeroed; `buffer_.alignment_` (`+0x48`) =
`alignment_`; `buffer_.buf_` (`+0x50`) = `nullptr`;
`buffer_.capacity_` (`+0x58`) and `buffer_.cursize_` (`+0x60`)
zeroed; `buffer_.bufstart_` (`+0x68`) = `nullptr`;
`buffer_offset_` (`+0x70`) and `read_offset_` (`+0x78`) zeroed.
(The `+0x40` store is the last 8 bytes of the 40-byte mutex.)

**8. AllocateNewBuffer (0x6048cf2..0x6048d2f).** `new_capacity =
Roundup(readahead_size_, alignment_)` -- recomputed, equals
`readahead_size_` since it is already a multiple (upstream
`util/aligned_buffer.h:258`); `buf_ = new char[new_capacity +
alignment_]` (PLT `_Znam` 0x63f0e30, size `alignment_ +
readahead_size_`); `capacity_` (`+0x58`) = `new_capacity`;
`cursize_` (`+0x60`) = 0; `bufstart_` (`+0x68`) = `(buf_ +
alignment_ - 1) & -alignment_`; the old `buf_` (`nullptr` here)
is `delete[]`'d only if non-null (0x6048d33..0x6048d38, skipped).

**9. Return (0x6048d3d..0x6048d4e).** `out->ptr` = the new object;
return `out`.

Layout (pinned by the disassembly AND upstream
`sequence_file_reader.cc:552-581`, declaration order):

| offset | member | notes |
|---|---|---|
| `+0x00` | vptr | `ReadaheadSequentialFile` vtable (`0x64d1d80`) |
| `+0x08` | `file_` (`std::unique_ptr<FSSequentialFile>`) | the moved-in wrapped file |
| `+0x10` | `alignment_` (`const size_t`) | the SECOND `GetRequiredBufferAlignment()` call |
| `+0x18` | `readahead_size_` (`const size_t`) | `Roundup(readahead_size, alignment_)` |
| `+0x20` | `lock_` (`std::mutex`, 40 B) | zeroed |
| `+0x48` | `buffer_.alignment_` (`size_t`) | = `alignment_` |
| `+0x50` | `buffer_.buf_` (`std::unique_ptr<char[]>`) | `new char[capacity + alignment]` |
| `+0x58` | `buffer_.capacity_` (`size_t`) | = `readahead_size_` |
| `+0x60` | `buffer_.cursize_` (`size_t`) | 0 |
| `+0x68` | `buffer_.bufstart_` (`char*`) | `(buf_ + alignment_ - 1) & -alignment_` |
| `+0x70` | `buffer_offset_` (`uint64_t`) | 0 |
| `+0x78` | `read_offset_` (`uint64_t`) | 0 |

The vtable at `0x64d1d80` (typeinfo at `0x64d1d78` ->
`0x64d1d58`), from the `.rela.dyn` `R_X86_64_RELATIVE` entries --
the file bytes there are zero (a PIE `.data.rel.ro` vtable,
resolved at load):

| slot | target | method |
|---|---|---|
| 0 (`0x64d1d80`) | `0x6048640` | D1 complete destructor |
| 1 (`0x64d1d88`) | `0x6048680` | D0 deleting destructor |
| 2 (`0x64d1d90`) | `0x60486f0` | `Read` |
| 3 (`0x64d1d98`) | `0x6048ac0` | `Skip` |
| 4 (`0x64d1da0`) | `0x6048630` | `use_direct_io` (delegating thunk) |
| 5 (`0x64d1da8`) | `0x6025720` | `GetRequiredBufferAlignment` (inherited default, returns 4096) |
| 6 (`0x64d1db0`) | `0x60489e0` | `InvalidateCache` |
| 7 (`0x64d1db8`) | `0x60485e0` | `PositionedRead` (arg plumbing left open) |

The slot order matches upstream `FSSequentialFile`'s virtual
declaration order (`include/rocksdb/file_system.h:1298-1415`):
`Read`, `Skip`, `use_direct_io`, `GetRequiredBufferAlignment`
(returning `kDefaultPageSize`), `InvalidateCache`,
`PositionedRead`, `GetTemperature`. The default
`GetRequiredBufferAlignment` (`0x6025720`) is five bytes: `mov
$0x1000, %eax; ret` -- so a plain file reports 4096 and takes
the move path for any `readahead_size <= 4096`.

## The .cold landing pad (0x6048bfe..0x6048c30)

The LSDA call-site table was decoded from `.gcc_except_table`
by hand (the FDE's CIE is `zPLR`; the LSDA is uleb128-encoded,
3 entries, all with action 0):

| call-site range | call | landing pad |
|---|---|---|
| FDE+0x1d..+0x52 | gate `GetRequiredBufferAlignment()` (0x6048c4d) + `operator new(0x80)` (0x6048c7d) | NONE -- nothing constructed yet |
| FDE+0x72..+0x75 | ctor's `GetRequiredBufferAlignment()` (0x6048ca2) | `0x6048d5b` -> `0x6048c0c` (skips the `buf_` delete[]) |
| FDE+0xd7..+0xdc | `operator new[]` (0x6048d07) | `0x6048d4f` -> `0x6048bfe` (full cleanup) |

Full entry (`0x6048bfe`): `delete[] buffer_.buf_` (`+0x50`) if
non-null; delete `file_` (`+0x8`) via its virtual deleting
destructor (vtable slot 1) if non-null; sized `operator delete`
(0x80 bytes); `_Unwind_Resume`. Second entry (`0x6048c0c`):
the same minus the `buf_` delete[] -- `buf_` is still null at
the ctor's alignment call. (`buf_` is also still null at the
`new[]` call site, so that delete[] is a no-op in practice;
the compiler assigned the full pad anyway.)

## Caller census

Whole-`.text` E8/E9/LEA scan, Capstone-validated (see `census.py`):
exactly **4 direct calls**, 0 tail jumps, 0 LEA refs. All four
are the `SequentialFileReader` readahead constructor's init-list
call (`file/sequence_file_reader.h:150-154`,
`file_(NewReadaheadSequentialFile(std::move(_file),
_readahead_size), io_tracer, _file_name)`) -- inlined at three
sites, plus the standalone constructor FDE:

| site | caller FDE | caller |
|---|---|---|
| 0x5e6a40a | 0x5e68fd0..0x5e6b82a | `rocksdb::DBImpl::RecoverLogFiles` |
| 0x5e7fcff | 0x5e7f950..0x5e8061d | `rocksdb::DBImplSecondary::MaybeInitLogReader` |
| 0x5f7569f | 0x5f75640..0x5f75a33 | `rocksdb::SequentialFileReader::SequentialFileReader` (readahead ctor) |
| 0x60cfec4 | 0x60cfb60..0x60d1354 | `rocksdb::RocksDBOptionsParser::Parse` |

At each inlined site the call is followed by the shared_ptr
copy (`0x5d35c00`, `std::__shared_count` copy) installing the
`io_tracer` into the `SequentialFileReader`'s `file_` wrapper --
exactly the ctor's `file_(..., io_tracer, _file_name)`. `Parse`
reaches it through the inlined `LineFileReader`
forwarding-template ctor (`file/line_file_reader.h:28-30`),
which forwards to this readahead ctor; that is also how the
#6228 `ReadLine` packet's reader gets its readahead wrapper.

## Evidence

- `tools/sequential_file_reader_new_readahead115.py` -- the
  factory model.
- `tests/test_sequential_file_reader_new_readahead115.py` -- 28
  tests, all pass.
- `cases.tsv` -- 2,400 deterministic cases (600 gate + 600
  rounding + 600 layout + 600 bindings), 0 mismatches on replay
  (`python3 tools/sequential_file_reader_new_readahead115.py --verify`).
- Live engine check (`--live`): all 9 legs pass -- a plain file
  with the default alignment 4096 and readahead 8192 wraps with
  the exact layout fields (and the wrapped file's bytes read back
  equal the real file), readahead == alignment moves, readahead 0
  moves, alignment 1 wraps with a 101-byte buffer, a non-power
  alignment (100) rounds exactly, a misaligned heap base aligns
  `bufstart_` by the mask formula, a lying file takes its gate
  from call 1 and its layout from call 2, alignment 0 moves at
  readahead 0 and faults at readahead 1, and the `.cold`
  cleanup record matches the LSDA.
- `records.json` -- semantic records only (never a per-instruction
  mnemonic list); `functions.tsv`, `callers.tsv`, `census.json` --
  the census above.
- `MANIFEST.sha256` verifies clean; `tools/verify_packets.py` flags
  only the pre-existing mismatch in unrelated packet
  RE-001-adjacent-last-115 (present on clean upstream main, untouched).
- Excerpts are whole-FDE and verbatim (`.hex` + `.objdump.txt`,
  main + `.cold`), with the repo-relative binary path
  `work/hl-node-115.bin` (no absolute home paths).

## Upstream cross-check

`meta/rocksdb` v8.1.1, read live this cycle, confirms the packet
step for step: `file/sequence_file_reader.cc:588-610` defines
`NewReadaheadSequentialFile` (the `>=` gate with the
short-circuit comment at 594-600, then `new
ReadaheadSequentialFile` at 604-608); `:283-583` defines
`ReadaheadSequentialFile` (the ctor init list at 297-317:
`file_`, `alignment_` from `GetRequiredBufferAlignment()`,
`readahead_size_ = Roundup(readahead_size, alignment_)`,
`buffer_()`, `buffer_offset_(0)`, `read_offset_(0)`, then
`buffer_.Alignment(alignment_)` and
`buffer_.AllocateNewBuffer(readahead_size_)`; members at
552-581 in the same order as the binary layout);
`file/sequence_file_reader.h:136-162` declares the readahead
ctor overload that calls it, and `:209-215` declares the
factory itself; `util/aligned_buffer.h:62` defines `Roundup`
and `:236-290` `AllocateNewBuffer` (`new_capacity =
Roundup(requested_capacity, alignment_)`, `new char[new_capacity
+ alignment_]`, `bufstart_` aligned, `capacity_ = new_capacity`,
`cursize_ = 0`); `include/rocksdb/file_system.h:1298-1415`
declares `FSSequentialFile`'s virtuals in vtable order.

Binary-vs-source observations, recorded not hidden:

- The binary calls `GetRequiredBufferAlignment()` TWICE (gate,
  then ctor init list) and never reuses the first result.
- The binary's `Roundup` is div-based (`(x + y - 1) - (x + y - 1)
  % y`), matching upstream's `((x + y - 1) / y) * y`.
- The vendor census mislabels `0x6048640` as
  `ReadaheadRandomAccessFile::D1`; the binary proves it is
  `ReadaheadSequentialFile::D1` -- it resets the vptr to
  `0x64d1d80` (the sequential vtable), frees `+0x50` with
  `delete[]` and virtual-deletes `+0x8`, i.e. exactly this
  class's members. (The two destructors' source bytes are
  identical modulo the vtable LEA; the census picked the wrong
  candidate. The D0 at `0x6048680` is labelled correctly and ends
  with the sized delete of the 0x80-byte object.)
- The census's `0x60485e0` label (`PositionedRead`) is recorded
  but its arg plumbing is left open: the prologue loads
  `0x8(%rsi)`, which does not match a plain `(offset, n, opts,
  result, scratch, dbg)` forward. It forwards to the wrapped
  file's vtable slot 7, which IS `PositionedRead` in the
  declaration order, so the slot assignment stands; only the
  arg mapping is unpinned.
- `FSSequentialFile::GetRequiredBufferAlignment`'s default
  returns `kDefaultPageSize` (4096), proven by the 5-byte
  `0x6025720` body (`mov $0x1000, %eax; ret`) in vtable slot 5.
  A plain file therefore takes the move path for any
  `readahead_size <= 4096`.
- The LSDA's first call-site entry covers BOTH the gate call
  and the `operator new(0x80)` call with no landing pad; the
  two throwing points after construction starts get the two
  distinct pads (the `new[]` pad is the full cleanup even
  though `buf_` is still null there).
- `bufstart_` uses the mask formula `(buf_ + alignment_ - 1) &
  -alignment_`, a true AlignUp only for power-of-two
  alignments; upstream requires that (`AlignedBuffer::Alignment`
  asserts `(alignment & (alignment - 1)) == 0`, compiled out),
  so non-power-of-two alignments are outside the contract and
  the mask can round `bufstart_` DOWN. The model reproduces the
  binary's arithmetic exactly rather than a textbook AlignUp.

## Open unknowns (not claimed)

- The wrapped file's `Read`/`Skip`/`PositionedRead`/
  `InvalidateCache`/`use_direct_io` methods (vtable slots
  2-4, 6-7) are NOT modelled here -- only the factory and the
  inlined constructor it feeds. Their record bytes are their
  own subjects.
- The exact arg mapping of the `PositionedRead` override at
  `0x60485e0` (see above) is unpinned; only its vtable slot
  and its forward to the wrapped file's slot 7 are claimed.
- The TLS-free `std::mutex` at `+0x20` is modelled as 40 zero
  bytes; the mutex's runtime state (locked/unlocked) is not
  observable from this factory alone.
- Heap addresses are modelled as deterministic fake bases, not
  real pointers; the buffer bytes are uninitialised `new char[]`
  and are modelled as a size, not content.
