#!/usr/bin/env python3
"""Node #115 RocksDB SequentialFileReader::NewReadaheadSequentialFile:
reconstruction.

RE-002 work item. Reconstructs the readahead-wrapper factory at
0x6048c30..0x6048d67 (311 B) plus its landing pad .cold at
0x6048bfe..0x6048c30 (50 B), the static factory the
``SequentialFileReader`` readahead constructor calls to wrap a raw
``FSSequentialFile`` in a ``ReadaheadSequentialFile`` when the
requested readahead exceeds the file's required buffer alignment:

  rocksdb::SequentialFileReader::NewReadaheadSequentialFile
      0x6048c30 (311 B) + .cold 0x6048bfe (50 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
BOTH FDEs are vendor-census-bound (member
a895f7517936a0f7-sequence_file_reader.o, librocksdb-sys
0.11.0+8.1.1): the main FDE body hash 487104cb... and the .cold
body hash 204e9c9a... were recomputed from the binary, and the
source hashes 2acc4f4d... / 017b892e... were reproduced exactly by
zeroing the census relocations (6 / 3, kinds 2/4).

What the binary does (whole-FDE disassembly, verbatim in the packet):

  std::unique_ptr<FSSequentialFile> NewReadaheadSequentialFile(
      std::unique_ptr<FSSequentialFile>&& file, size_t readahead_size)
  -- rdi is the hidden sret (the out unique_ptr), rsi the input
  unique_ptr*, rdx the readahead_size. Steps, in binary order:

  1. Gate (0x6048c47..0x6048c53): alignment =
     file->GetRequiredBufferAlignment() -- the call at 0x6048c4d
     is the virtual call through vtable slot 5 (0x28(%rax)); if
     alignment >= readahead_size, go to the move path (step 2).
     This is upstream sequence_file_reader.cc:594, including the
     short-circuit comment ("return the original file if
     readahead_size is too small and hence doesn't make sense to
     be used for prefetching"). The comparison is unsigned
     (jb); equality takes the move path.
  2. Move path (0x6048c55..0x6048c72): out->ptr = file.ptr;
     file.ptr = nullptr (the move); return out. The input
     unique_ptr is left null, exactly std::move(file).
  3. Wrap path (0x6048c78..): operator new(0x80) for the
     ReadaheadSequentialFile object (PLT _Znwm 0x63f0dd0).
  4. vptr + file_ (0x6048c82..0x6048c9e): the input file pointer
     is moved out (file.ptr = nullptr, 0x6048c86) and stored at
     +0x8; the vtable pointer at +0x0 is the LEA at 0x6048c91
     to 0x64d1d80 -- the ReadaheadSequentialFile vtable (proven
     by its .rela.dyn entries: slot 0 D1 0x6048640, slot 1 D0
     0x6048680, slot 2 Read 0x60486f0, slot 3 Skip 0x6048ac0,
     slot 4 use_direct_io 0x6048630, slot 5
     GetRequiredBufferAlignment 0x6025720 (the inherited
     FSSequentialFile default, returning kDefaultPageSize 4096),
     slot 6 InvalidateCache 0x60489e0, slot 7 PositionedRead
     0x60485e0; typeinfo at 0x64d1d78 -> 0x64d1d58).
  5. Second alignment call (0x6048c9b..0x6048ca2): alignment =
     file_->GetRequiredBufferAlignment() AGAIN -- the constructor
     init-list call (sequence_file_reader.cc:303); the binary
     does NOT reuse the gate result. alignment_ (+0x10) is set
     from this second call. A file whose two calls disagree
     takes the gate from call 1 and the layout from call 2;
     the model records both.
  6. Roundup (0x6048ca5..0x6048ced): readahead_size_ (+0x18) =
     Roundup(readahead_size, alignment_) -- ((x + y - 1) / y) * y
     via div (util/aligned_buffer.h:62), i.e. (x + y - 1) -
     (x + y - 1) % y. This is upstream
     sequence_file_reader.cc:305. If alignment_ is 0 here the
     div faults (#DE, exactly Roundup(x, 0)); the model raises
     ZeroDivisionError for that case. It can only happen when
     readahead_size > 0 and the file reports alignment 0 (the
     gate 0 < readahead_size already passed).
  7. AlignedBuffer init (0x6048cb6..0x6048ce9): lock_ (+0x20,
     std::mutex, 40 bytes) zeroed; buffer_.alignment_ (+0x48) =
     alignment_; buffer_.buf_ (+0x50) = nullptr;
     buffer_.capacity_ (+0x58) and buffer_.cursize_ (+0x60)
     zeroed; buffer_.bufstart_ (+0x68) = nullptr;
     buffer_offset_ (+0x70) and read_offset_ (+0x78) zeroed.
     (The +0x40 store is the last 8 bytes of the 40-byte mutex.)
  8. AllocateNewBuffer (0x6048cf2..0x6048d2f): new_capacity =
     Roundup(readahead_size_, alignment_) -- recomputed, equals
     readahead_size_ since it is already a multiple (upstream
     util/aligned_buffer.h:258); buf_ = new char[new_capacity +
     alignment_] (PLT _Znam 0x63f0e30, size alignment_ +
     readahead_size_); capacity_ (+0x58) = new_capacity;
     cursize_ (+0x60) = 0; bufstart_ (+0x68) =
     AlignUp(buf_, alignment_) = (buf_ + alignment_ - 1) &
     -alignment_; the old buf_ (nullptr here) is delete[]'d
     only if non-null (0x6048d33..0x6048d38, skipped).
  9. Return (0x6048d3d..0x6048d4e): out->ptr = the new object;
     return out.

Layout of ReadaheadSequentialFile (0x80 bytes, pinned by the
disassembly AND upstream sequence_file_reader.cc:552-581,
declaration order):

  +0x00  vptr            ReadaheadSequentialFile vtable (0x64d1d80)
  +0x08  file_           std::unique_ptr<FSSequentialFile>
  +0x10  alignment_      const size_t (2nd GetRequiredBufferAlignment)
  +0x18  readahead_size_ const size_t (Roundup(readahead, alignment_))
  +0x20  lock_           std::mutex (40 B, zeroed)
  +0x48  buffer_.alignment_  size_t (= alignment_)
  +0x50  buffer_.buf_    std::unique_ptr<char[]> (new char[cap + align])
  +0x58  buffer_.capacity_   size_t (= readahead_size_)
  +0x60  buffer_.cursize_    size_t (0)
  +0x68  buffer_.bufstart_   char* (AlignUp(buf_, alignment_))
  +0x70  buffer_offset_  uint64_t (0)
  +0x78  read_offset_    uint64_t (0)

The .cold landing pad (0x6048bfe..0x6048c30, LSDA call-site
table decoded from .gcc_except_table -- see records.json):
three call-site entries, all with action 0:

  FDE+0x1d..+0x52  the gate GetRequiredBufferAlignment() call
                   (0x6048c4d) and the operator new(0x80) call
                   (0x6048c7d) -> NO landing pad: nothing has
                   been constructed yet, the exception
                   propagates with no cleanup.
  FDE+0x72..+0x75  the ctor's GetRequiredBufferAlignment() call
                   (0x6048ca2) -> landing pad 0x6048d5b, which
                   jumps to 0x6048c0c: it SKIPS the buf_ delete[]
                   (buf_ is still null), deletes file_ via its
                   virtual deleting destructor (slot 1) if
                   non-null, then sized-deletes the 0x80-byte
                   object and resumes unwinding.
  FDE+0xd7..+0xdc  the operator new[] call (0x6048d07) ->
                   landing pad 0x6048d4f, which jumps to
                   0x6048bfe: the FULL cleanup -- delete[] buf_
                   (+0x50) if non-null, delete file_ (+0x8) via
                   its virtual deleting destructor if non-null,
                   sized-delete the object, resume unwinding.
                   (buf_ is still null at the new[] call site,
                   so the delete[] is a no-op in practice; the
                   compiler assigned the full pad anyway.)

Caller census (whole-.text scan, Capstone-validated): exactly
FOUR direct calls, 0 tail jumps, 0 LEA refs. All four are the
SequentialFileReader readahead constructor's init-list call
(file/sequence_file_reader.h:150-154,
``file_(NewReadaheadSequentialFile(std::move(_file),
_readahead_size), io_tracer, _file_name)``) -- inlined at three
sites, plus the standalone constructor FDE:

  0x5e6a40a  rocksdb::DBImpl::RecoverLogFiles 0x5e68fd0..0x5e6b82a
  0x5e7fcff  rocksdb::DBImplSecondary::MaybeInitLogReader
            0x5e7f950..0x5e8061d
  0x5f7569f  rocksdb::SequentialFileReader::SequentialFileReader
            (the readahead ctor overload) 0x5f75640..0x5f75a33
  0x60cfec4  rocksdb::RocksDBOptionsParser::Parse 0x60cfb60..0x60d1354

At each inlined site the call is followed by the shared_ptr
copy (0x5d35c00, std::__shared_count copy) that installs the
io_tracer into the SequentialFileReader's file_ wrapper --
exactly the ctor's ``file_(..., io_tracer, _file_name)``. Parse
reaches it through the inlined LineFileReader forwarding
template ctor (file/line_file_reader.h:28-30), which forwards
to this readahead ctor; that is also how the #6228 ReadLine
packet's reader gets its readahead wrapper.

Upstream cross-check (meta/rocksdb v8.1.1, read live this
cycle): file/sequence_file_reader.cc:588-610 defines
NewReadaheadSequentialFile (the >= gate with the short-circuit
comment, then ``new ReadaheadSequentialFile``); :283-583
defines ReadaheadSequentialFile (the ctor init list at
297-317: file_, alignment_ from GetRequiredBufferAlignment(),
readahead_size_ = Roundup(readahead_size, alignment_),
buffer_(), buffer_offset_(0), read_offset_(0), then
buffer_.Alignment(alignment_) and
buffer_.AllocateNewBuffer(readahead_size_); members at
552-581 in the same order as the binary layout);
file/sequence_file_reader.h:136-162 declares the readahead
ctor overload that calls it, and :209-215 declares the
factory itself; util/aligned_buffer.h:62 defines Roundup and
:236-290 AllocateNewBuffer (new_capacity = Roundup(requested,
alignment_), new char[new_capacity + alignment_], bufstart_
aligned, capacity_ = new_capacity, cursize_ = 0);
include/rocksdb/file_system.h:1298-1415 declares
FSSequentialFile's virtuals in vtable order (Read, Skip,
use_direct_io, GetRequiredBufferAlignment returning
kDefaultPageSize, InvalidateCache, PositionedRead,
GetTemperature), which matches the relocated vtable slots
exactly -- including the inherited default
GetRequiredBufferAlignment returning 4096 (0x6025720).

Binary-vs-source observations, recorded not hidden:

- The binary calls GetRequiredBufferAlignment() TWICE (gate,
  then ctor init list) and never reuses the first result.
- The binary's Roundup is div-based ((x + y - 1) -
  (x + y - 1) % y), matching upstream's ((x + y - 1) / y) * y.
- The vendor census mislabels 0x6048640 as
  ReadaheadRandomAccessFile::D1; the binary proves it is
  ReadaheadSequentialFile::D1 -- it resets the vptr to
  0x64d1d80 (the sequential vtable), frees +0x50 with
  delete[] and virtual-deletes +0x8, i.e. exactly this
  class's members. (The two destructors' source bytes are
  identical modulo the vtable LEA; the census picked the
  wrong candidate. The D0 at 0x6048680 is labelled correctly
  and ends with the sized delete of the 0x80-byte object.)
- The census's 0x60485e0 label (PositionedRead) is recorded
  but its arg plumbing is left open: the prologue loads
  0x8(%rsi), which does not match a plain (offset, n, opts,
  result, scratch, dbg) forward. It forwards to the wrapped
  file's vtable slot 7, which IS PositionedRead in the
  declaration order, so the slot assignment stands; only the
  arg mapping is unpinned.
- FSSequentialFile::GetRequiredBufferAlignment's default
  returns kDefaultPageSize (4096), proven by the 5-byte
  0x6025720 body (mov $0x1000, %eax; ret) in vtable slot 5.
  A plain file therefore takes the move path for any
  readahead_size <= 4096.
- The LSDA's first call-site entry covers BOTH the gate call
  and the operator new(0x80) call with no landing pad; the
  two throwing points after construction starts get the two
  distinct pads (the new[] pad is the full cleanup even
  though buf_ is still null there).

Environment limits (stated honestly): no cargo/rustc/git-lfs/
Ghidra on this VM; the model is Python evidence, not a Rust
reconstruction; the wrapped file's Read/Skip/etc. are
scripted as oracles (their record bytes are the
ReadaheadSequentialFile::Read/Skip subjects, not reimplemented
here); heap addresses are modelled as deterministic fake
bases, not real pointers; the buffer bytes are
uninitialised new char[] and are modelled as a size, not
content.
"""
import hashlib
import json
import random
import sys
import tempfile
from pathlib import Path

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
PACKET = Path(__file__).resolve().parents[1] / "research" / "work-items" / \
    "re-002-node115-sequential-file-reader-new-readahead-115"
CASES = PACKET / "cases.tsv"

# Binary facts.
FDE_START = 0x6048C30
FDE_END = 0x6048D67
COLD_START = 0x6048BFE
COLD_END = 0x6048C30
VTABLE = 0x64D1D80
OBJECT_SIZE = 0x80  # sizeof(ReadaheadSequentialFile)
MUTEX_SIZE = 40  # std::mutex (pthread_mutex_t)
KDEFAULTPAGESIZE = 4096  # FSSequentialFile::GetRequiredBufferAlignment default

# The ReadaheadSequentialFile layout (offsets from the disassembly
# + upstream sequence_file_reader.cc:552-581).
LAYOUT = {
    "vptr": 0x00,
    "file_": 0x08,
    "alignment_": 0x10,
    "readahead_size_": 0x18,
    "lock_": 0x20,
    "buffer_alignment_": 0x48,
    "buffer_buf_": 0x50,
    "buffer_capacity_": 0x58,
    "buffer_cursize_": 0x60,
    "buffer_bufstart_": 0x68,
    "buffer_offset_": 0x70,
    "read_offset_": 0x78,
}

# The vtable slots (relocated .rela.dyn entries at 0x64d1d80).
VTABLE_SLOTS = {
    "0x64d1d80": "0x6048640",  # D1 (complete destructor)
    "0x64d1d88": "0x6048680",  # D0 (deleting destructor)
    "0x64d1d90": "0x60486f0",  # Read
    "0x64d1d98": "0x6048ac0",  # Skip
    "0x64d1da0": "0x6048630",  # use_direct_io (delegating thunk)
    "0x64d1da8": "0x6025720",  # GetRequiredBufferAlignment (default: 4096)
    "0x64d1db0": "0x60489e0",  # InvalidateCache
    "0x64d1db8": "0x60485e0",  # PositionedRead
}

# The LSDA call-site table (decoded from .gcc_except_table).
LSDA_SITES = [
    {"start": "0x6048c4d", "end": "0x6048c50",
     "landing_pad": None,
     "note": "gate GetRequiredBufferAlignment() call + operator new(0x80): "
             "no cleanup yet"},
    {"start": "0x6048ca2", "end": "0x6048ca5",
     "landing_pad": "0x6048d5b",
     "note": "ctor GetRequiredBufferAlignment() call: pad skips the buf_ "
             "delete[] (buf_ is null), deletes file_, deletes the object"},
    {"start": "0x6048d07", "end": "0x6048d0c",
     "landing_pad": "0x6048d4f",
     "note": "operator new[] call: full cleanup (delete[] buf_, delete "
             "file_, delete the object)"},
]

# The four validated caller sites.
CALLERS = [
    {"site": "0x5e6a40a", "fde_start": "0x5e68fd0",
     "fde_end": "0x5e6b82a",
     "name": "rocksdb::DBImpl::RecoverLogFiles"},
    {"site": "0x5e7fcff", "fde_start": "0x5e7f950",
     "fde_end": "0x5e8061d",
     "name": "rocksdb::DBImplSecondary::MaybeInitLogReader"},
    {"site": "0x5f7569f", "fde_start": "0x5f75640",
     "fde_end": "0x5f75a33",
     "name": "rocksdb::SequentialFileReader::SequentialFileReader"
             "(readahead ctor)"},
    {"site": "0x60cfec4", "fde_start": "0x60cfb60",
     "fde_end": "0x60d1354",
     "name": "rocksdb::RocksDBOptionsParser::Parse"},
]


def roundup(x, y):
    """Upstream Roundup (util/aligned_buffer.h:62):
    ((x + y - 1) / y) * y, computed by the binary as
    (x + y - 1) - (x + y - 1) % y. A zero alignment faults
    (#DE) in the binary; the model raises ZeroDivisionError."""
    if y == 0:
        raise ZeroDivisionError("Roundup by zero alignment")
    return ((x + y - 1) // y) * y


def align_up(addr, alignment):
    """The binary's exact bufstart_ computation (0x6048d20..0x6048d2f):
    (addr + alignment - 1) & -alignment (== & ~(alignment - 1)).
    This is a true AlignUp only when alignment is a power of two
    -- upstream requires that (AlignedBuffer::Alignment asserts
    (alignment & (alignment - 1)) == 0, compiled out here), so
    non-power-of-two alignments are outside the contract and the
    mask formula can even round DOWN (a negative offset). The
    model reproduces the binary's arithmetic exactly rather than
    a textbook AlignUp."""
    if alignment == 0:
        raise ZeroDivisionError("AlignUp by zero alignment")
    return (addr + alignment - 1) & ~(alignment - 1)


class FakeFSSequentialFile:
    """An FSSequentialFile oracle: only
    GetRequiredBufferAlignment() is modelled (the factory's only
    query); Read/Skip/etc. are the ReadaheadSequentialFile method
    subjects, not reimplemented here. ``alignment2`` lets a case
    script a file whose second call disagrees with its first --
    the binary calls the virtual twice and never reuses the
    first result."""

    def __init__(self, file_id, alignment, alignment2=None, data=b""):
        self.file_id = file_id
        self.alignment = alignment
        self.alignment2 = alignment if alignment2 is None else alignment2
        self.data = bytes(data)
        self.offset = 0
        self.calls = []
        self.ptr = file_id  # the unique_ptr's pointer; None after move

    def get_required_buffer_alignment(self):
        self.calls.append("get_required_buffer_alignment")
        if len(self.calls) == 1:
            return self.alignment
        return self.alignment2

    def read(self, n):
        """A plain sequential read, for the live check only: the
        wrapper delegates to the same file, so these bytes are
        the wrapped object's bytes too."""
        chunk = self.data[self.offset:self.offset + n]
        self.offset += len(chunk)
        return chunk


class RealFSSequentialFile:
    """An FSSequentialFile backed by a real file on disk (for
    --live). The alignment is the oracle input; 4096 is the
    FSSequentialFile default (0x6025720 returns 0x1000)."""

    def __init__(self, path, file_id="real-file", alignment=4096):
        self.path = Path(path)
        self.file_id = file_id
        self.alignment = alignment
        self.calls = []
        self.ptr = file_id
        self.fh = open(self.path, "rb")

    def get_required_buffer_alignment(self):
        self.calls.append("get_required_buffer_alignment")
        return self.alignment

    def read(self, n):
        return self.fh.read(n)

    def close(self):
        self.fh.close()


def new_readahead_sequential_file(file, readahead_size,
                                  alloc_base=0x100000000):
    """The NewReadaheadSequentialFile model. Returns the result
    dict; the trace lists every binary step in order. ``file``
    is a FakeFSSequentialFile / RealFSSequentialFile oracle;
    ``alloc_base`` is the deterministic fake heap base for the
    new char[] allocation (the model records sizes and the
    aligned start offset, never real pointers)."""
    trace = []
    # 1. Gate: alignment = file->GetRequiredBufferAlignment().
    alignment_gate = file.get_required_buffer_alignment()
    trace.append({"op": "get_alignment", "call": 1,
                  "value": alignment_gate})
    # 2. Move path: alignment >= readahead_size.
    if alignment_gate >= readahead_size:
        out_id = file.ptr
        file.ptr = None
        trace.append({"op": "move", "out_file_id": out_id})
        return {"wrapped": False,
                "out_file_id": out_id,
                "input_null_after": file.ptr is None,
                "alignment_gate": alignment_gate,
                "readahead_size": readahead_size,
                "trace": trace}
    # 5. Second alignment call (ctor init list).
    alignment_ctor = file.get_required_buffer_alignment()
    trace.append({"op": "get_alignment", "call": 2,
                  "value": alignment_ctor})
    # 6. readahead_size_ = Roundup(readahead_size, alignment_).
    #    A zero alignment faults here in the binary (#DE).
    rounded = roundup(readahead_size, alignment_ctor)
    trace.append({"op": "roundup", "x": readahead_size,
                  "y": alignment_ctor, "result": rounded})
    # 8. AllocateNewBuffer(readahead_size_): new_capacity =
    #    Roundup(readahead_size_, alignment_) == rounded.
    capacity = roundup(rounded, alignment_ctor)
    alloc_size = capacity + alignment_ctor
    trace.append({"op": "allocate", "new_capacity": capacity,
                  "alloc_size": alloc_size})
    bufstart = align_up(alloc_base, alignment_ctor)
    trace.append({"op": "bufstart", "buf_base": hex(alloc_base),
                  "bufstart": hex(bufstart),
                  "offset": bufstart - alloc_base})
    # The file pointer is moved into file_ (0x6048c82..0x6048c9e).
    wrapped_id = file.ptr
    file.ptr = None
    obj = {
        "vtable": hex(VTABLE),
        "size": OBJECT_SIZE,
        "file_": wrapped_id,
        "alignment_": alignment_ctor,
        "readahead_size_": rounded,
        "lock_zero_bytes": MUTEX_SIZE,
        "buffer_alignment_": alignment_ctor,
        "buffer_buf_size": alloc_size,
        "buffer_capacity_": capacity,
        "buffer_cursize_": 0,
        "buffer_bufstart": hex(bufstart),
        "buffer_bufstart_offset": bufstart - alloc_base,
        "buffer_offset_": 0,
        "read_offset_": 0,
    }
    trace.append({"op": "return_wrapped", "object_size": OBJECT_SIZE})
    return {"wrapped": True,
            "object": obj,
            "alignment_gate": alignment_gate,
            "alignment_ctor": alignment_ctor,
            "readahead_size": readahead_size,
            "alloc_base": hex(alloc_base),
            "input_null_after": file.ptr is None,
            "trace": trace}


def cold_cleanup(buf_set, file_set):
    """The .cold landing-pad cleanup (0x6048bfe..0x6048c30),
    as a record: delete[] buffer_.buf_ (+0x50) if non-null,
    virtual-delete file_ (+0x8) if non-null, sized-delete the
    0x80-byte object, _Unwind_Resume. The second pad
    (0x6048d5b -> 0x6048c0c) skips the buf_ delete[] because
    buf_ is still null at the ctor's alignment call."""
    steps = []
    if buf_set:
        steps.append("delete[] buffer_.buf_ (+0x50)")
    if file_set:
        steps.append("virtual-delete file_ (+0x8, vtable slot 1)")
    steps.append("sized operator delete (0x80 bytes)")
    steps.append("_Unwind_Resume")
    return steps


def run_case(inputs):
    """Run one case: build the oracle file, run the factory,
    return the expected-output dict."""
    alignment2 = inputs.get("alignment2")
    fake = FakeFSSequentialFile(
        inputs["file_id"], inputs["alignment"],
        alignment2=alignment2)
    try:
        result = new_readahead_sequential_file(
            fake, inputs["readahead_size"], inputs["alloc_base"])
    except ZeroDivisionError:
        return {"wrapped": None, "error": "ZeroDivisionError",
                "alignment_gate": inputs["alignment"],
                "readahead_size": inputs["readahead_size"],
                "calls": len(fake.calls)}
    result["alignment_calls"] = len(fake.calls)
    return result

def _gen_group(rng, group, n):
    rows = []
    for i in range(n):
        case_id = "%s-%03d" % (group, i)
        inputs = {"case_id": case_id, "group": group}
        if group == "gate":
            # The move/wrap boundary: alignment vs readahead_size.
            alignment = rng.choice(
                [0, 1, 1, 2, 3, 7, 8, 512, 512, 4096, 4096, 4096,
                 8192, 16384])
            readahead = rng.choice(
                [0, 0, 1, 2, 3, 4095, 4096, 4096, 4097, 8192, 8192,
                 16384, 100000])
            # Bias half the rows to sit exactly on the boundary.
            if rng.random() < 0.5:
                alignment = rng.choice([1, 512, 4096, 8192])
                readahead = rng.choice(
                    [alignment - 1 if alignment > 1 else 0,
                     alignment, alignment + 1])
            inputs.update({
                "file_id": "file-%s" % case_id,
                "alignment": alignment,
                "readahead_size": readahead,
                "alloc_base": 0x100000000 + i * 97,
            })
        elif group == "rounding":
            # Roundup(readahead, alignment) + the AllocateNewBuffer
            # recomputation, across powers and non-powers of two.
            alignment = rng.choice(
                [1, 2, 3, 5, 7, 16, 100, 512, 1000, 4096, 4096, 8192])
            if rng.random() < 0.5:
                readahead = rng.choice(
                    [0, 1, alignment - 1, alignment, alignment + 1,
                     2 * alignment - 1, 2 * alignment,
                     2 * alignment + 1, 3 * alignment,
                     10 * alignment + 3])
            else:
                readahead = rng.choice(
                    [1, 7, 100, 1000, 4097, 8191, 8192, 8193, 16385,
                     100000, 1000000])
            # The wrap path needs readahead > alignment; force it
            # for most rows so the rounding is exercised.
            if readahead <= alignment and rng.random() < 0.8:
                readahead = alignment + rng.choice(
                    [1, 7, alignment - 1, alignment, 1000])
            inputs.update({
                "file_id": "file-%s" % case_id,
                "alignment": alignment,
                "readahead_size": readahead,
                "alloc_base": 0x7F0000000000 + i * 0x1111,
            })
        elif group == "layout":
            # Whole-object field layout for wrapped objects, with
            # aligned and misaligned fake heap bases.
            alignment = rng.choice([1, 2, 16, 512, 4096, 4096, 8192])
            readahead = alignment + rng.choice(
                [1, alignment, 2 * alignment, 100, 4096])
            base = rng.choice([
                0x100000000,  # aligned to 4096
                0x100000001,  # off by one
                0x100001234,  # arbitrary misalignment
                0x7F0000000000 + i * 97,
            ])
            inputs.update({
                "file_id": "file-%s" % case_id,
                "alignment": alignment,
                "readahead_size": readahead,
                "alloc_base": base,
            })
        elif group == "bindings":
            # End-to-end traces: lying files (call 2 disagrees),
            # the default 4096 alignment, huge readaheads, and
            # move-path bindings.
            kind = rng.choice(["lying", "default", "huge", "move",
                               "plain"])
            if kind == "lying":
                alignment = rng.choice([512, 4096])
                alignment2 = rng.choice([1, 2, 1024, 8192])
                readahead = rng.choice(
                    [alignment + 1, alignment + 4096, 100000])
                inputs.update({
                    "file_id": "file-%s" % case_id,
                    "alignment": alignment,
                    "alignment2": alignment2,
                    "readahead_size": readahead,
                    "alloc_base": 0x100000000 + i * 13,
                })
            elif kind == "default":
                inputs.update({
                    "file_id": "file-%s" % case_id,
                    "alignment": KDEFAULTPAGESIZE,
                    "readahead_size": rng.choice(
                        [4096, 4097, 8192, 16384, 100000]),
                    "alloc_base": 0x100000000 + i * 29,
                })
            elif kind == "huge":
                inputs.update({
                    "file_id": "file-%s" % case_id,
                    "alignment": rng.choice([512, 4096]),
                    "readahead_size": rng.choice(
                        [1 << 20, 1 << 24, 1 << 30]),
                    "alloc_base": 0x100000000 + i * 31,
                })
            elif kind == "move":
                alignment = rng.choice([4096, 8192])
                inputs.update({
                    "file_id": "file-%s" % case_id,
                    "alignment": alignment,
                    "readahead_size": rng.choice(
                        [0, 1, alignment - 1, alignment]),
                    "alloc_base": 0x100000000 + i * 7,
                })
            else:
                alignment = rng.choice([1, 512, 4096])
                inputs.update({
                    "file_id": "file-%s" % case_id,
                    "alignment": alignment,
                    "readahead_size": alignment + rng.choice([1, 4096]),
                    "alloc_base": 0x100000000 + i * 11,
                })
        expected = run_case(inputs)
        rows.append((group, case_id, inputs, expected))
    return rows


def write_cases():
    all_rows = []
    for gi, group in enumerate(
            ["gate", "rounding", "layout", "bindings"]):
        rng = random.Random(115000 + gi)
        all_rows.extend(_gen_group(rng, group, 600))
    with open(CASES, "w") as fh:
        fh.write("group\tcase_id\tinputs_json\texpected_json\n")
        for group, case_id, inputs, expected in all_rows:
            fh.write("%s\t%s\t%s\t%s\n" % (
                group, case_id,
                json.dumps(inputs, sort_keys=True),
                json.dumps(expected, sort_keys=True)))
    print("wrote %d cases to %s" % (len(all_rows), CASES))


def verify_cases():
    rows = []
    with open(CASES) as fh:
        header = fh.readline().rstrip("\n").split("\t")
        for line in fh:
            rows.append(dict(zip(header, line.rstrip("\n").split("\t"))))
    mismatches = 0
    for row in rows:
        inputs = json.loads(row["inputs_json"])
        expected = json.loads(row["expected_json"])
        got = run_case(inputs)
        if got != expected:
            mismatches += 1
            print("MISMATCH %s:\n  got %s\n  exp %s" % (
                row["case_id"], json.dumps(got, sort_keys=True),
                json.dumps(expected, sort_keys=True)))
            if mismatches >= 3:
                break
    print("verify: %d cases, %d mismatches"
          % (len(rows), mismatches))
    return mismatches == 0 and len(rows) == 2400


def live_engine_check():
    """Drive real files through the model in a temp dir. 9 legs."""
    report = {"ok": False, "legs": []}
    try:
        # Leg 1: plain file, default alignment 4096, readahead
        # 8192 -- wrapped; the layout fields are exactly the
        # binary's arithmetic.
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "opts.txt"
            data = (b"[Version]\nrocksdb_version=8.1.1\n\n"
                    b"[DBOptions]\nmax_open_files=12345\n")
            p.write_bytes(data)
            f = RealFSSequentialFile(p, alignment=4096)
            res = new_readahead_sequential_file(f, 8192)
            assert res["wrapped"] is True
            obj = res["object"]
            assert obj["alignment_"] == 4096
            assert obj["readahead_size_"] == 8192
            assert obj["buffer_capacity_"] == 8192
            assert obj["buffer_buf_size"] == 8192 + 4096
            assert obj["buffer_cursize_"] == 0
            assert obj["buffer_offset_"] == 0
            assert obj["read_offset_"] == 0
            assert obj["lock_zero_bytes"] == 40
            assert obj["vtable"] == hex(VTABLE)
            assert obj["size"] == 0x80
            assert int(obj["buffer_bufstart"], 16) % 4096 == 0
            assert obj["file_"] == "real-file"
            assert f.ptr is None  # moved into file_
            # The wrapped file_ is the same real file: its bytes
            # read back equal the file on disk.
            assert f.read(len(data)) == data
            f.close()
            report["legs"].append({"leg": "wrap_default_alignment",
                                  "ok": True})
        # Leg 2: readahead == alignment (4096) -- the move path:
        # the same file comes back, the input is nulled.
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "a.txt"
            p.write_bytes(b"hello")
            f = RealFSSequentialFile(p, file_id="f2", alignment=4096)
            res = new_readahead_sequential_file(f, 4096)
            assert res["wrapped"] is False
            assert res["out_file_id"] == "f2"
            assert res["input_null_after"] is True
            assert len(f.calls) == 1  # only the gate call
            f.close()
            report["legs"].append({"leg": "move_equal_alignment",
                                  "ok": True})
        # Leg 3: readahead 0 -- the move path (0 <= alignment).
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "b.txt"
            p.write_bytes(b"hello")
            f = RealFSSequentialFile(p, file_id="f3", alignment=4096)
            res = new_readahead_sequential_file(f, 0)
            assert res["wrapped"] is False
            assert res["out_file_id"] == "f3"
            f.close()
            report["legs"].append({"leg": "move_zero_readahead",
                                  "ok": True})
        # Leg 4: alignment 1, readahead 100 -- wrapped with no
        # rounding (Roundup(100, 1) == 100) and a 101-byte buffer.
        with tempfile.TemporaryDirectory() as root:
            p = Path(root) / "c.txt"
            p.write_bytes(b"x" * 500)
            f = RealFSSequentialFile(p, file_id="f4", alignment=1)
            res = new_readahead_sequential_file(f, 100)
            assert res["wrapped"] is True
            obj = res["object"]
            assert obj["readahead_size_"] == 100
            assert obj["buffer_capacity_"] == 100
            assert obj["buffer_buf_size"] == 101
            f.close()
            report["legs"].append({"leg": "wrap_alignment_one",
                                  "ok": True})
        # Leg 5: non-power-of-two alignment 100, readahead 1000 --
        # Roundup(1000, 100) == 1000, buffer 1100 bytes.
        f = FakeFSSequentialFile("f5", 100)
        res = new_readahead_sequential_file(f, 1000)
        assert res["wrapped"] is True
        assert res["object"]["readahead_size_"] == 1000
        assert res["object"]["buffer_buf_size"] == 1100
        assert res["object"]["buffer_capacity_"] == 1000
        report["legs"].append({"leg": "non_power_alignment",
                              "ok": True})
        # Leg 6: a misaligned fake heap base -- bufstart is the
        # AlignUp, the offset is in [0, alignment), and the
        # capacity is unchanged.
        f = FakeFSSequentialFile("f6", 4096)
        base = 0x100000001
        res = new_readahead_sequential_file(f, 8192,
                                            alloc_base=base)
        obj = res["object"]
        assert obj["buffer_bufstart_offset"] == 4095
        assert int(obj["buffer_bufstart"], 16) == base + 4095
        assert int(obj["buffer_bufstart"], 16) % 4096 == 0
        report["legs"].append({"leg": "misaligned_base",
                              "ok": True})
        # Leg 7: lying file -- the second alignment call differs;
        # the gate uses call 1, the layout uses call 2.
        f = FakeFSSequentialFile("f7", 4096, alignment2=512)
        res = new_readahead_sequential_file(f, 8192)
        assert res["wrapped"] is True
        assert res["alignment_gate"] == 4096
        assert res["alignment_ctor"] == 512
        assert res["object"]["alignment_"] == 512
        assert res["object"]["readahead_size_"] == 8192
        assert res["object"]["buffer_buf_size"] == 8192 + 512
        assert len(f.calls) == 2
        report["legs"].append({"leg": "lying_file_two_calls",
                              "ok": True})
        # Leg 8: alignment 0 -- readahead 0 takes the move path
        # (0 >= 0); readahead 1 faults in Roundup (#DE).
        f = FakeFSSequentialFile("f8", 0)
        res = new_readahead_sequential_file(f, 0)
        assert res["wrapped"] is False
        f = FakeFSSequentialFile("f8b", 0)
        try:
            new_readahead_sequential_file(f, 1)
            raise AssertionError("expected ZeroDivisionError")
        except ZeroDivisionError:
            pass
        report["legs"].append({"leg": "zero_alignment_edge",
                              "ok": True})
        # Leg 9: the .cold cleanup record -- full cleanup frees
        # the buffer and the file; the second pad skips the
        # buffer delete (buf_ is null at the ctor's alignment
        # call).
        full = cold_cleanup(True, True)
        assert full == ["delete[] buffer_.buf_ (+0x50)",
                        "virtual-delete file_ (+0x8, vtable slot 1)",
                        "sized operator delete (0x80 bytes)",
                        "_Unwind_Resume"]
        partial = cold_cleanup(False, True)
        assert partial[0].startswith("virtual-delete file_")
        assert len(LSDA_SITES) == 3
        assert LSDA_SITES[1]["landing_pad"] == "0x6048d5b"
        assert LSDA_SITES[2]["landing_pad"] == "0x6048d4f"
        report["legs"].append({"leg": "cold_cleanup_record",
                              "ok": True})
        report["ok"] = True
    except Exception as exc:  # noqa: BLE001 - report, do not raise
        report["ok"] = False
        report["error"] = repr(exc)
    print("live engine check:", json.dumps(report))
    return report["ok"], report


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true",
                    help="replay cases.tsv through the model")
    ap.add_argument("--gen-cases", action="store_true",
                    help="generate cases.tsv")
    ap.add_argument("--live", action="store_true",
                    help="run the live engine check")
    args = ap.parse_args(argv)
    ok = True
    if args.gen_cases:
        write_cases()
    if args.verify:
        ok = verify_cases() and ok
    if args.live:
        live_ok, _ = live_engine_check()
        ok = live_ok and ok
    if not (args.gen_cases or args.verify or args.live):
        ap.print_help()
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
