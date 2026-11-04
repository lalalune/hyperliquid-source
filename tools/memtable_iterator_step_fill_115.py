"""Model for the node #115 memtable iterator step-and-fill 0x5f08790
(RE-014 validation).

Every rule below is pinned to the verbatim disassembly in
research/work-items/RE-014-memtable-iterator-step-fill-115/. The
reader (0x5f07670), the report routine (0x5fceda0), the known step
(0x5f08600) and the varint decoder (0x61bd4f0) are taken by contract
— their call sites, arguments and return handling are pinned, while
their internals are not claimed here. The dispatch, predicate gate,
fill gate, reader install/report rule, provider gate and
length-prefix fill are modeled and tested here.
"""


def decode_varint(data, limit=5):
    """Bounded LEB128 decode, as the 0x61bd4f0 contract: at most
    `limit` bytes are consumed (the window passes buffer + 5 as the
    limit). Returns (value, bytes_consumed). Raises ValueError on a
    truncated or over-long encoding.
    """
    value = 0
    for i in range(limit):
        if i >= len(data):
            raise ValueError("varint truncated")
        byte = data[i]
        value |= (byte & 0x7F) << (7 * i)
        if byte < 0x80:
            return value, i + 1
    raise ValueError("varint exceeds the 5-byte bound")


def parse_length_prefix(buf):
    """Inline length-prefix parse of the default-provider path.

    First byte below 0x80 is the length itself and the slice starts
    one byte later; otherwise a bounded varint at the buffer start
    gives the length and the slice starts past the varint.
    Returns (offset, length).
    """
    if not buf:
        raise ValueError("empty buffer")
    first = buf[0]
    if first < 0x80:
        return 1, first
    value, consumed = decode_varint(buf)
    return consumed, value


class StepFill:
    """Executable model of 0x5f08790 with injectable callees.

    Callables (each recorded in `events` in call order):
      dispatch_slot(): the +0x38 slot when it is not the known step.
      inner_advance(): the inner +0x20 virtual.
      inner_valid(): the inner +0x10 virtual; returns a bool.
      predicate(): the +0x10 virtual when it is not the known one;
        returns a bool.
      reader(): installs a status; returns (code, subcode, detail).
      report(): the levelled report on a nonzero reader code.
      provider(): the +0x50 slot when it is not the default one;
        returns (pointer, length).
      default_buffer(): the inner +0x18 buffer for the inline parse.
    Fixed inputs: known_step (bool), predicate_known (bool),
    provider_default (bool), width (this+0x60), perf_byte (the TLS
    perf byte), plus counters for the perf block.
    """

    def __init__(self, **kw):
        self.events = []
        self.counters = {"perf_148": 0}
        self.reported = []
        # On the dispatch-unequal path the called +0x38 slot performs
        # the step itself, so valid/status arrive preset by that slot
        # rather than from the inline inner advance; the caller may
        # seed them via initial_valid / initial_status.
        self.status = kw.get("initial_status", (0, 0, None))
        self.valid = bool(kw.get("initial_valid", False))
        self.cfg = kw

    def _call(self, name):
        self.events.append(name)
        fn = self.cfg.get(name)
        return fn() if fn is not None else None

    def run(self):
        cfg = self.cfg
        # Dispatch: unequal +0x38 slot is called and the perf block
        # and inline inner advance are skipped.
        if not cfg.get("known_step", True):
            self._call("dispatch_slot")
        else:
            if cfg.get("perf_byte", 0) > 1:
                self._call("perf_helper")
                self.counters["perf_148"] += 1
            self._call("inner_advance")
            self.valid = bool(self._call("inner_valid"))
        width = cfg.get("width", 0)
        if width:
            if cfg.get("predicate_known", True):
                if not self.valid:
                    return False, None
                self._reader()
            else:
                pred = self._call("predicate")
                if not pred:
                    # Rejoin the shared check: the predicate is
                    # called a second time and must be True.
                    if not self._call("predicate"):
                        return False, None
                    return self._provider()
                if not self.valid:
                    return False, None
                self._reader()
            # After the reader: shared check, then the fill gate.
            if cfg.get("predicate_known", True):
                if not (self.valid and self.status[0] == 0):
                    return False, None
            else:
                if not self._call("predicate"):
                    return False, None
                if not (self.valid and self.status[0] == 0):
                    return False, None
            return self._provider()
        # Width zero: no reader. Known predicate -> fill gate;
        # unknown predicate True -> provider, False -> False.
        if cfg.get("predicate_known", True):
            if not (self.valid and self.status[0] == 0):
                return False, None
        else:
            if not self._call("predicate"):
                return False, None
        return self._provider()

    def _reader(self):
        code, sub, detail = self._call("reader")
        old_detail = self.status[2]
        self.status = (code, sub, detail)
        if old_detail is not None:
            self.events.append("free_old_detail")
        if code != 0:
            self._call("report")
            self.reported.append(detail)

    def _provider(self):
        if self.cfg.get("provider_default", True):
            buf = self.cfg["default_buffer"]()
            offset, length = parse_length_prefix(buf)
            out = (offset, length, 0x100)
        else:
            pointer, length = self._call("provider")
            out = (pointer, length, 0x100)
        return True, out
