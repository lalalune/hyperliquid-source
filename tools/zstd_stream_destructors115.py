"""Node #115 RocksDB ZSTD streaming destructors: reconstruction.

RE-002 work item. Reconstructs the four destructor functions at
0x5f014f0..0x5f03a64:

  rocksdb::ZSTDStreamingCompress::~ZSTDStreamingCompress (D0)  0x5f03a10 (45 B)
  rocksdb::ZSTDStreamingCompress::~ZSTDStreamingCompress (D1)  0x5f03a40 (36 B)
  rocksdb::ZSTDStreamingUncompress::~ZSTDStreamingUncompress (D0) 0x5f014f0 (45 B)
  rocksdb::ZSTDStreamingUncompress::~ZSTDStreamingUncompress (D1) 0x5f01520 (36 B)

Bound to node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Each body hash matches the vendor census target_body_sha256 exactly, and
each census source_body_sha256 is reproduced by zeroing the recorded
relocation fields (the vtable lea additionally needs the kind-42
mov<-lea restoration; see records.json). Symbols come from the vendor
census (member 25dac13516458d4d-log_writer.o / -log_reader.o,
librocksdb-sys); the vtable slots are pinned by the two merged vtable
packets (compress 0x64d7418 slots 0/1, uncompress 0x64d7448 slots 0/1).

What the binary does, per function (whole-FDE disassembly, verbatim in
the packet):

  D1 (both classes): store the most-derived vtable address point into
  [this+0x00] FIRST (lea of the vtable header + 0x10), then call the
  engine free on the context slot ([this+0x50] CCtx / [this+0x18] DCtx),
  then return. Nothing else is touched: the inBuffer is a plain struct
  with no destructor, and the ctx slot is NOT nulled after the free.
  D0 (both classes): the same two steps INLINED (D0 does not call D1),
  then tail-jumps to sized operator delete (_ZdlPvm) with the holder
  size (0x70 compress / 0x38 uncompress) as the second argument.

The engine free functions are ZSTD_freeCCtx 0x6219ac0 (FDE
0x6219ac0..0x6219c13) and ZSTD_freeDCtx 0x628c1e0 (FDE
0x628c1e0..0x628c3cb, census symbol confirmed). Both are null-tolerant:
test rdi,rdi; je to `xor eax,eax; ret` (free(NULL) returns 0 and frees
nothing). The freeCCtx identification is by shape + role + twin: it is
called with the CCtx the ctor created (0x6218920, pinned by the merged
RE-001-zstd-compress-cache-115 packet), it has the same null-guard
prologue and the same free-the-workspace body shape as the
census-confirmed freeDCtx, and it is the only zstd free that takes a
CCtx. The return value of both frees is ignored by the destructors.
This closes the merged RE-001-zstd-compress-cache-115 packet's open
unknown ("no separate freeCCtx was found in the census"; "the 0x70-byte
holder's teardown is unpinned").

Caller census (census.py, whole-.text E8/E9/LEA scan, Capstone-validated
from enclosing FDE starts): ZERO direct calls, tail jumps or LEA refs to
any of the four destructors. They are vtable-only: destruction reaches
them through vtable slots 0 (D1) and 1 (D0). D0 inlining D1 instead of
calling it is why D1 has no caller at all.

What is modelled here is the destructor's OBSERVABLE trace: the ordered
events (vptr store, engine free, operator delete) plus the resulting
state (ctx freed, holder memory freed by D0 only, ctx slot left
un-nulled). The engine free is driven through the system libzstd.so.1
(1.5.5) via ctypes on a REAL context handle, so a live destroy really
frees a real CCtx/DCtx. Two sequences the binary would execute but this
tool refuses to execute literally, because they are undefined behaviour
in the test process: a second free of an already-freed ctx (the binary
never nulls the slot, so D1-then-D1 would double-free) and any access
to a holder after D0 freed it. The model DETECTS both (registry +
freed-holder guard) and records them as outcomes instead of executing
them; see :func:`destroy_d1` / :func:`destroy_d0`.

Object layouts (from the merged factory packet #5857, re-verified here
through the operator-delete sizes): compress holder 0x70 bytes (vptr
+0x00, CCtx* +0x50, inBuffer +0x58..+0x70); uncompress holder 0x38 bytes
(vptr +0x00, DCtx* +0x18, inBuffer +0x20..+0x38).

Upstream anchors (RocksDB v8.1.1, confirmed by source read):
  * The destructors are INLINE in util/compression.h, not in .cc:
    ~ZSTDStreamingCompress() at lines 1754-1758 calls
    ZSTD_freeCCtx(cctx_) under #ifdef ZSTD_STREAMING and does nothing
    else; ~ZSTDStreamingUncompress() at lines 1779-1783 calls
    ZSTD_freeDCtx(dctx_) the same way. Both ignore the return value.
    ZSTD_STREAMING is defined (compression.h:56-58) when
    ZSTD_VERSION_NUMBER >= 10400; in a non-streaming build the bodies
    are empty.
  * Members (compression.h): ZSTDStreamingCompress (line 1739) holds
    ZSTD_CCtx* cctx_ (1763) + ZSTD_inBuffer input_buffer_ (1764);
    ZSTDStreamingUncompress (1768) holds ZSTD_DCtx* dctx_ (1789) +
    ZSTD_inBuffer input_buffer_ (1790). The layout derives exactly the
    binary sizes: compress base 80 B (vptr 8 + 1-byte CompressionType +
    48-byte CompressionOptions + u32 format_version + size_t
    max_output_len) + cctx_ 8 + input_buffer_ 24 = 112 = 0x70;
    uncompress base 24 B + dctx_ 8 + input_buffer_ 24 = 56 = 0x38.
    Both derived classes are final; the destructors are override
    (virtual), and the bases declare virtual default destructors --
    so deletion through a base pointer dispatches through the vtable
    D0 slot, consistent with the zero-direct-caller census.
  * ZSTD_freeCCtx(NULL) / ZSTD_freeDCtx(NULL) return 0 (zstd v1.5.5,
    lib/compress/zstd_compress.c:181 and lib/decompress/
    zstd_decompress.c:323: `if (cctx==NULL) return 0; /* support free
    on NULL */`; both declarations carry an `/* accept NULL pointer */`
    comment). The D0 sized delete is compiler-generated, not source.

Environment limits (stated honestly): no cargo/rustc/git-lfs/Ghidra on
this VM; the target binary is never executed; the ZSTD engine calls go
to the system libzstd, not to the target binary.
"""

import ctypes
import ctypes.util
import hashlib
import json
import random
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
COMPRESS_VPTR = 0x64D7418
UNCOMPRESS_VPTR = 0x64D7448
COMPRESS_SIZE = 0x70
UNCOMPRESS_SIZE = 0x38
COMPRESS_CTX_OFF = 0x50
UNCOMPRESS_CTX_OFF = 0x18

_lib = None


def _load_lib():
    global _lib
    if _lib is None:
        try:
            _lib = ctypes.CDLL(ctypes.util.find_library("zstd") or "libzstd.so.1")
        except OSError as exc:
            raise RuntimeError(
                "system libzstd.so.1 is required to drive the ZSTD engine "
                "(the target binary statically links zstd 1.5.7; this tool "
                "uses the system 1.5.5 through the same public API)"
            ) from exc
        _lib.ZSTD_versionString.restype = ctypes.c_char_p
        _lib.ZSTD_createCCtx.restype = ctypes.c_void_p
        _lib.ZSTD_createDCtx.restype = ctypes.c_void_p
        _lib.ZSTD_freeCCtx.argtypes = [ctypes.c_void_p]
        _lib.ZSTD_freeCCtx.restype = ctypes.c_size_t
        _lib.ZSTD_freeDCtx.argtypes = [ctypes.c_void_p]
        _lib.ZSTD_freeDCtx.restype = ctypes.c_size_t
    return _lib


class DoubleFree(Exception):
    """Second free of an already-freed engine context (model-detected)."""


class UseAfterFree(Exception):
    """Access to a holder whose memory D0 already freed (model-detected)."""


class CtxRegistry:
    """Live engine-context handles. A second free of the same handle is
    detected here and never reaches the real free (that would be UB)."""

    def __init__(self):
        self._live = {}   # handle int -> "ccctx" | "dctx"
        self._freed = set()

    def create_ccctx(self):
        lib = _load_lib()
        h = lib.ZSTD_createCCtx()
        if not h:
            raise RuntimeError("ZSTD_createCCtx returned NULL")
        self._live[h] = "ccctx"
        return h

    def create_dctx(self):
        lib = _load_lib()
        h = lib.ZSTD_createDCtx()
        if not h:
            raise RuntimeError("ZSTD_createDCtx returned NULL")
        self._live[h] = "dctx"
        return h

    def free_ccctx(self, handle):
        """Returns the size_t the binary ignores (0). NULL is a no-op,
        exactly like the binary's callee (test rdi,rdi; je -> ret 0)."""
        if handle is None or handle == 0:
            return 0
        if handle in self._freed:
            raise DoubleFree(f"CCtx {handle:#x} already freed")
        if self._live.get(handle) != "ccctx":
            raise DoubleFree(f"CCtx {handle:#x} not a live CCtx")
        ret = _load_lib().ZSTD_freeCCtx(handle)
        del self._live[handle]
        self._freed.add(handle)
        return ret

    def free_dctx(self, handle):
        if handle is None or handle == 0:
            return 0
        if handle in self._freed:
            raise DoubleFree(f"DCtx {handle:#x} already freed")
        if self._live.get(handle) != "dctx":
            raise DoubleFree(f"DCtx {handle:#x} not a live DCtx")
        ret = _load_lib().ZSTD_freeDCtx(handle)
        del self._live[handle]
        self._freed.add(handle)
        return ret

    def live_count(self):
        return len(self._live)


class Holder:
    """A fake-heap holder object: bytearray memory + liveness flag.

    Layout: [vptr:8][...][ctx*:8][inBuffer...]. The memory is only
    readable while the holder is live; D0 frees it.
    """

    def __init__(self, family, registry, ctx_live=True):
        self.family = family  # "compress" | "uncompress"
        self.registry = registry
        self.size = COMPRESS_SIZE if family == "compress" else UNCOMPRESS_SIZE
        self.vptr = COMPRESS_VPTR if family == "compress" else UNCOMPRESS_VPTR
        self.ctx_off = (COMPRESS_CTX_OFF if family == "compress"
                        else UNCOMPRESS_CTX_OFF)
        self.mem = bytearray(self.size)
        self.live = True
        if ctx_live:
            self.ctx = (registry.create_ccctx() if family == "compress"
                        else registry.create_dctx())
        else:
            self.ctx = 0
        # The factory wrote the vptr at construction; the destructor
        # stores it again (the store is the first destructor event).
        self._write_vptr(self.vptr)
        self._write_ctx(self.ctx)

    def _check_live(self):
        if not self.live:
            raise UseAfterFree("holder memory already freed by D0")

    def _write_vptr(self, value):
        struct.pack_into("<Q", self.mem, 0, value)

    def _write_ctx(self, value):
        struct.pack_into("<Q", self.mem, self.ctx_off, value)

    def read_vptr(self):
        self._check_live()
        return struct.unpack_from("<Q", self.mem, 0)[0]

    def read_ctx_slot(self):
        """The ctx slot value. The binary never nulls it after the free,
        so a post-D1 read still returns the (freed) handle."""
        self._check_live()
        return struct.unpack_from("<Q", self.mem, self.ctx_off)[0]


def destroy_d1(holder):
    """Model of the D1 (complete-object) destructor.

    Events, in binary order: store vptr, free ctx. Returns the event
    list. The holder memory stays allocated; the ctx slot is left
    holding the freed handle value (the binary never nulls it).
    Raises DoubleFree on a second D1 of the same holder.
    """
    holder._check_live()
    events = []
    holder._write_vptr(holder.vptr)
    events.append(("store_vptr", hex(holder.vptr)))
    ctx = holder.read_ctx_slot()
    if ctx:
        if holder.family == "compress":
            holder.registry.free_ccctx(ctx)
        else:
            holder.registry.free_dctx(ctx)
        events.append(("free_ctx", hex(ctx)))
    else:
        # free(NULL) is a no-op in the binary's callee; the destructor
        # still issued the call, so the event is recorded as a null free.
        events.append(("free_ctx", "null-noop"))
    return events


def destroy_d0(holder):
    """Model of the D0 (deleting) destructor.

    Events, in binary order: store vptr, free ctx, operator delete with
    the holder size. D0 does NOT call D1: the first two steps are the
    inlined D1 body. After this call the holder memory is freed and any
    access raises UseAfterFree. Raises DoubleFree on a second D0/D1 of
    the same holder (via the registry, before the real free).
    """
    holder._check_live()
    events = []
    holder._write_vptr(holder.vptr)
    events.append(("store_vptr", hex(holder.vptr)))
    ctx = holder.read_ctx_slot()
    if ctx:
        if holder.family == "compress":
            holder.registry.free_ccctx(ctx)
        else:
            holder.registry.free_dctx(ctx)
        events.append(("free_ctx", hex(ctx)))
    else:
        events.append(("free_ctx", "null-noop"))
    events.append(("operator_delete", holder.size))
    holder.live = False
    holder.mem = None
    return events


def make_holder(family, ctx_live=True):
    """Fresh holder + its own registry (one registry per case keeps the
    double-free accounting independent)."""
    registry = CtxRegistry()
    return Holder(family, registry, ctx_live=ctx_live), registry


# ---------------------------------------------------------------------------
# Deterministic case generation (2,400 cases).
# ---------------------------------------------------------------------------

def generate_cases(seed=115):
    """Yield 2,400 case dicts.

    Split: 600 compress-live + 600 uncompress-live (each 200 D1, 200 D0,
    100 D1-then-D1 double-free, 100 D0-then-D1 use-after-free) + 600
    null-ctx (150 per family per destructor) + 600 ordering/size (150
    per family per destructor: vptr value, event order, delete size).
    Expected outcomes are computed from the binary-derived rules, not
    by running the tool: D1 frees the ctx once and leaves the holder
    live; D0 frees the ctx once and frees the holder with the family
    size; a second destroy of the same holder double-frees the ctx
    (D1-then-D1) or touches freed memory (D0-then-D1); a null ctx makes
    the free a no-op.
    """
    rng = random.Random(seed)
    cases = []

    def add(family, ctx, sequence, group):
        cases.append({
            "id": f"{group}-{len(cases):04d}",
            "family": family,
            "ctx": ctx,
            "sequence": sequence,
            "group": group,
        })

    for family in ("compress", "uncompress"):
        for _ in range(200):
            add(family, "live", ["d1"], "live")
        for _ in range(200):
            add(family, "live", ["d0"], "live")
        for _ in range(100):
            add(family, "live", ["d1", "d1"], "live")
        for _ in range(100):
            add(family, "live", ["d0", "d1"], "live")
    for family in ("compress", "uncompress"):
        for _ in range(150):
            add(family, "null", ["d1"], "null-ctx")
        for _ in range(150):
            add(family, "null", ["d0"], "null-ctx")
    for family in ("compress", "uncompress"):
        for _ in range(150):
            add(family, "live", ["d1"], "ordering")
        for _ in range(150):
            add(family, "live", ["d0"], "ordering")
    rng.shuffle(cases)
    for i, c in enumerate(cases):
        c["id"] = f"case-{i:04d}"
    assert len(cases) == 2400
    return cases


def expected_outcome(case):
    """Binary-derived expected outcome for a case, independent of the
    tool's destroy functions."""
    seq = case["sequence"]
    if seq == ["d1"]:
        return "ok-d1"
    if seq == ["d0"]:
        return "ok-d0"
    if seq == ["d1", "d1"]:
        return "double-free"
    if seq == ["d0", "d1"]:
        return "use-after-free"
    raise ValueError(case)


def replay_case(case):
    """Run a case through the model; return (events, outcome). The
    outcome is one of ok-d1 / ok-d0 / double-free / use-after-free."""
    holder, _registry = make_holder(case["family"],
                                    ctx_live=(case["ctx"] == "live"))
    events = []
    outcome = None
    try:
        for op in case["sequence"]:
            if op == "d1":
                events.extend(destroy_d1(holder))
            else:
                events.extend(destroy_d0(holder))
        outcome = "ok-d1" if case["sequence"] == ["d1"] else "ok-d0"
    except DoubleFree:
        outcome = "double-free"
    except UseAfterFree:
        outcome = "use-after-free"
    return events, outcome


def cases_tsv_rows():
    """Rows for cases.tsv: id, family, ctx, sequence, expected outcome,
    expected delete size (0x70/0x38 for D0, - for D1-only), vptr."""
    rows = []
    for c in generate_cases():
        seq = "+".join(c["sequence"])
        delete_size = ""
        if c["sequence"] == ["d0"]:
            delete_size = str(COMPRESS_SIZE if c["family"] == "compress"
                              else UNCOMPRESS_SIZE)
        vptr = COMPRESS_VPTR if c["family"] == "compress" else UNCOMPRESS_VPTR
        rows.append((c["id"], c["family"], c["ctx"], seq,
                     expected_outcome(c), delete_size, hex(vptr),
                     c["group"]))
    return rows


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "gen-cases":
        out = ROOT / "research" / "work-items" / \
            "re-002-node115-zstd-stream-destructors-115" / "cases.tsv"
        rows = cases_tsv_rows()
        with open(out, "w") as fh:
            fh.write("id\tfamily\tctx\tsequence\texpected_outcome\t"
                     "delete_size\tvptr\tgroup\n")
            for r in rows:
                fh.write("\t".join(str(x) for x in r) + "\n")
        print(f"wrote {out} ({len(rows)} cases)")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
