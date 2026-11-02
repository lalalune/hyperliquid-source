"""Python model of node #94's WAL replay step 0x520ad30 (RE-001).

The model implements the behavior pinned by
research/work-items/RE-001-wal-replay-step-94/: the entry status copy,
the basename rule, the column-family filter, the arg1-byte gate, the
single logical-record read (mode 0, null transform), the short/long
dispatch at record length 11, the short-record log call, the
long-record apply and out move, the teardown arg5 rule, and the
teardown order. Callee internals (entry virtual calls, reader,
detail builder, formatter, log dispatcher, record-state constructor
internals, grow helper) are contracts: the model takes their pinned
observable inputs/outputs instead of reimplementing them.

Out status struct layout (bytearray of 16 bytes, matching the pinned
writes): u32 at +0, u16 at +4, pointer handle at +8 on the entry
copy; u16 at +0, u8 at +2, u16 at +3, u8 at +5, pointer handle at +8
on the short-path field copy; all three fields zeroed on the long
path move. Pointer handles refer to FakeHeap blocks; freeing the old
handle on the copy/move paths is part of the behavior.
"""

import struct

DEFAULT_METHOD = 0x4FA4610
SHORT_LIMIT = 11
LOG_FORMAT = "[%s:461] [WalManager] %s%s: dropping %d bytes; %s"
LOG_FILE = "db/wal_manager.cc"
SHORT_MESSAGE = "log record too small"
SHORT_CODE = 2
INVERTED_PREFIX = "(ignoring error) "
CLEAR_PREFIX = ""


class OutOfRangeError(ValueError):
    """Mirrors the substr out-of-range throw in the basename step."""


class FakeHeap:
    """Handle-keyed fake heap so frees are observable in tests."""

    def __init__(self):
        self.blocks = {}
        self.freed = []
        self._next = 1

    def alloc(self, data):
        handle = self._next
        self._next += 1
        self.blocks[handle] = bytes(data)
        return handle

    def free(self, handle):
        if handle:
            self.blocks.pop(handle, None)
            self.freed.append(handle)

    def read(self, handle):
        return self.blocks.get(handle)


class OutStatus:
    """The 16-byte out status struct, as a bytearray."""

    def __init__(self):
        self.raw = bytearray(16)

    @property
    def low_byte(self):
        return self.raw[0]

    def u32_at_0(self):
        return struct.unpack_from("<I", self.raw, 0)[0]

    def u16_at_4(self):
        return struct.unpack_from("<H", self.raw, 4)[0]

    def ptr_at_8(self):
        return struct.unpack_from("<Q", self.raw, 8)[0]


def basename_of(filename):
    """Basename rule: substring after the last '/' or '\\'.

    No separator means the whole filename. A start past the end
    raises, mirroring the substr throw block.
    """
    idx = max(filename.rfind("/"), filename.rfind("\\"))
    start = idx + 1 if idx >= 0 else 0
    if start > len(filename):
        raise OutOfRangeError(
            f"substr: __pos (which is {start}) > this->size() "
            f"(which is {len(filename)})"
        )
    return filename[start:]


def filter_elements(elements):
    """CF filter: keep only elements whose +0x140 method differs
    from the default 0x4fa4610 and whose method returns nonzero."""
    kept = []
    for element in elements:
        if element["method"] == DEFAULT_METHOD:
            continue
        if not element["pred"]:
            continue
        kept.append(element)
    return kept


class RecordState:
    """The 0x5219960-constructed record-state object (contract view)."""

    def __init__(self):
        self.string = b""
        self.flag_24 = 0

    def apply(self, record):
        """0x521cbf0: replace the +0x40 string with the record
        bytes and set +0x24 to 1. The caller zeroes the scratch."""
        self.string = bytes(record)
        self.flag_24 = 1

    def head_qword(self):
        """0x521b610: first qword of the +0x40 string data."""
        if len(self.string) < 8:
            raise ValueError("record too short for head qword")
        return struct.unpack_from("<Q", self.string, 0)[0]


class ReplayStep:
    """The replay step. Injected callables stand in for callees
    whose internals are contracts, not pinned behavior."""

    def __init__(self, heap=None, formatter=None):
        self.heap = heap or FakeHeap()
        # formatter(status_code, message) -> opaque formatted value
        self.formatter = formatter or (lambda code, msg: f"status:{code}:{msg}")
        self.log_records = []
        self.events = []
        self.state = None
        self.kept = []

    # -- phases -------------------------------------------------
    def _entry_copy(self, out, entry_status):
        u32, u16, ptr_data = entry_status
        struct.pack_into("<I", out.raw, 0, u32)
        struct.pack_into("<H", out.raw, 4, u16)
        # Observed: the entry copy overwrites out +8 without
        # freeing the previous handle.
        handle = self.heap.alloc(ptr_data) if ptr_data is not None else 0
        struct.pack_into("<Q", out.raw, 8, handle)

    def _build_state(self, filename, singleton_first):
        base = basename_of(filename)
        self.state = {
            "filename": filename,
            "basename": base,
            "singleton_first": singleton_first,
            "vector": [],
        }
        return self.state

    def _teardown_state_walk(self):
        self.events += [
            "state-vector-release",
            "state-subobject-50-release",
            "state-vcall-40",
            "state-subobject-28-release",
            "state-vcall-00",
            "state-free",
        ]

    def _teardown_full(self):
        self.events += [
            "accumulator-dispose",
            "reader-dtor",
            "handle-dispose",
        ]
        self._teardown_state_walk()
        self.events.append("trailing-release")

    def _teardown_rule(self, out, flag_7f, flag_7d):
        if out.low_byte == 0 and flag_7f == 0 and flag_7d != 0:
            return 1
        return 0

    def run(self, out, filename, elements, read_result, entry_status,
            singleton_first=0, inverted_flag=False, flag_7f=0,
            flag_7d=0, scratch=None):
        """Run one replay step.

        out: OutStatus (the arg1 struct; its low byte gates).
        filename: the arg3 filename string.
        elements: CF element dicts {method, pred, ptr, ref}.
        read_result: None for a failed read, else the record bytes.
        entry_status: (u32, u16, ptr_data|None) from the entry calls.
        scratch: 16-byte bytearray standing in for the -0x220
            scratch status on the short path (detail-builder output).
        Returns the arg5 value, or None when the gate path leaves
        arg5 unwritten.
        """
        self._entry_copy(out, entry_status)
        self._build_state(filename, singleton_first)
        self.kept = filter_elements(elements)
        self.state["vector"] = list(self.kept)

        if scratch is None:
            scratch = bytearray(16)

        if out.low_byte != 0:
            # Gate path: straight to state teardown, arg5 untouched.
            self._teardown_state_walk()
            self.events.append("trailing-release")
            return None

        # Reader construction is a contract event here.
        self.events.append("reader-construct")
        self.events.append("record-read")

        if read_result is None:
            arg5 = self._teardown_rule(out, flag_7f, flag_7d)
            self._teardown_full()
            return arg5

        record = bytes(read_result)
        if len(record) <= SHORT_LIMIT:
            formatted = self.formatter(SHORT_CODE, SHORT_MESSAGE)
            prefix = INVERTED_PREFIX if inverted_flag else CLEAR_PREFIX
            self.log_records.append({
                "level": 2,
                "format": LOG_FORMAT,
                "file": LOG_FILE,
                "prefix": prefix,
                "filename": filename,
                "length": len(record),
                "formatted": formatted,
            })
            self.events.append("log-short-record")
            if scratch is not None and out.low_byte == 0:
                # Status field copy (short path, out byte 0).
                old_ptr = out.ptr_at_8()
                out.raw[0:2] = scratch[0:2]
                out.raw[2] = scratch[2]
                out.raw[3:5] = scratch[3:5]
                out.raw[5] = scratch[5]
                scratch_ptr = struct.unpack_from("<Q", scratch, 8)[0]
                if scratch_ptr:
                    data = self.heap.read(scratch_ptr)
                    new_ptr = self.heap.alloc(data) if data is not None else 0
                else:
                    new_ptr = 0
                struct.pack_into("<Q", out.raw, 8, new_ptr)
                self.heap.free(old_ptr)
                self.events.append("status-field-copy")
            else:
                # Out byte nonzero: copy skipped, scratch buffer freed.
                if scratch is not None:
                    scratch_ptr = struct.unpack_from("<Q", scratch, 8)[0]
                    self.heap.free(scratch_ptr)
                self.events.append("status-copy-skipped")
            arg5 = self._teardown_rule(out, flag_7f, flag_7d)
            self._teardown_full()
            return arg5

        # Long path: construct, apply, move zeroed scratch, arg5.
        record_state = RecordState()
        self.events.append("record-state-construct")
        record_state.apply(record)
        self.events.append("record-apply")
        scratch_zero = bytearray(16)
        old_ptr = out.ptr_at_8()
        struct.pack_into("<I", out.raw, 0, 0)
        struct.pack_into("<H", out.raw, 4, 0)
        struct.pack_into("<Q", out.raw, 8, 0)
        self.heap.free(old_ptr)
        self.events.append("out-zero-move")
        arg5 = record_state.head_qword()
        self.events.append("record-state-reset")
        self._teardown_full()
        return arg5
