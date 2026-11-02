"""Python model of node #94's WAL replay caller loop (0x520d3a0..0x520e12e).

RE-001 work item. The model pins the caller loop's control flow exactly as
observed: entry-chain resolution, predicate gating, replay-driver call,
second-chain resolution, record append with reserve/grow, the type-1
retry arm, status copy/move rules, and teardown order. Callees whose
internals are not pinned (predicate, driver, filename builders, chain
handlers, vector helpers) are injected callables, so the model tests the
loop, not its callees.

Status struct (binary layout): u32 code at +0, u16 subcode at +4,
message pointer at +8. ``byte0`` is the low byte of the code. The binary
copies the six header bytes verbatim on every status transfer; the
message is string-copied on the entry and loop-end paths and moved on
the driver-fail and chain-fail paths. The model represents the message
as a string value and records copy-vs-move in the event log.
"""

RECORD_TAG_PTR = 0x575BDF0
CHAIN_SINGLETON_A = 0x5778260
CHAIN_SINGLETON_B = 0x57781E0
CHAIN_SINGLETON_RETRY = 0x5778258


class Status:
    """A 16-byte status struct: code (u32), subcode (u16), message."""

    def __init__(self, code=0, subcode=0, message=None):
        self.code = code & 0xFFFFFFFF
        self.subcode = subcode & 0xFFFF
        self.message = message

    @property
    def byte0(self):
        return self.code & 0xFF

    def header(self):
        return (self.code, self.subcode)

    def copy(self):
        """String-copy semantics: the message value is duplicated."""
        return Status(self.code, self.subcode,
                      None if self.message is None else str(self.message))

    def __eq__(self, other):
        return isinstance(other, Status) and \
            (self.code, self.subcode, self.message) == \
            (other.code, other.subcode, other.message)

    def __repr__(self):
        return f"Status(code={self.code}, subcode={self.subcode}, " \
               f"message={self.message!r})"


class ChainNode:
    """One chain link: the identity value at the node's identity field."""

    def __init__(self, identity_value):
        self.identity_value = identity_value


def resolve_chain(nodes, singleton):
    """Ten-comparison-plus-fallback resolution (all three chain kinds).

    Compare the head object plus nine successive +0x48 links (ten
    comparisons) against the runtime singleton. The first node whose
    identity differs wins; if all ten compare equal, the next node's
    handler (index 10) is called. ``nodes`` must hold at least eleven
    entries; shorter chains resolve to their last node.
    """
    for i in range(min(10, len(nodes))):
        if nodes[i].identity_value != singleton:
            return i
    return min(10, len(nodes) - 1)


class Record:
    """One 0x28-byte appended record (pointer-sized fields as values)."""

    def __init__(self, log_number, file_type, slot_value, handler_slot):
        self.tag_ptr = RECORD_TAG_PTR
        self.log_number = log_number
        self.file_type = file_type
        self.slot_value = slot_value
        self.handler_slot = handler_slot

    def __eq__(self, other):
        return isinstance(other, Record) and self.__dict__ == other.__dict__

    def __repr__(self):
        return f"Record(tag={self.tag_ptr:#x}, log={self.log_number}, " \
               f"type={self.file_type}, slot={self.slot_value!r}, " \
               f"handler_slot={self.handler_slot!r})"


class CallerLoop:
    """The caller loop with injected callees.

    ``world`` supplies: entry_handler(i) -> (Status, file_list),
    predicate(elem) -> (proceed_bool, gate_u32, log_number),
    driver(file_type, log_number, slot) -> (Status, slot_value),
    builder1(log_number) -> filename, builder0(log_number) -> filename,
    chain_b_handler(i) -> (Status, handler_slot_value),
    retry_a_handler(i) -> Status, retry_b_handler(i) -> (Status, slot),
    retry_a2_handler(i) -> Status; and chain node lists entry_nodes,
    chain_b_nodes, retry_a_nodes, retry_b_nodes, retry_a2_nodes.
    """

    def __init__(self, world, file_type):
        self.w = world
        self.file_type = file_type
        self.records = []
        self.capacity = 0
        self.events = []

    def _reserve(self, count):
        if self.capacity < count:
            self.capacity = count
            self.events.append(("reserve", count))

    def _append(self, record):
        if len(self.records) >= self.capacity:
            self.events.append(("grow", len(self.records)))
            self.capacity = max(1, self.capacity * 2)
        self.records.append(record)

    def _teardown_file_list(self, file_list):
        self.events.append(("teardown_file_list", len(file_list)))

    def run(self):
        w = self.w
        entry_idx = resolve_chain(w.entry_nodes, CHAIN_SINGLETON_A)
        entry_status, file_list = w.entry_handler(entry_idx)
        self.events.append(("entry_chain", entry_idx))
        if entry_status.byte0 != 0:
            out = entry_status.copy()
            self.events.append(("entry_fail_copy", out))
            self._teardown_file_list(file_list)
            return out
        self._reserve(len(file_list))
        loop_status = Status()
        for elem in file_list:
            proceed, gate, log_number = w.predicate(elem)
            if not proceed or gate != 0:
                self.events.append(("skip", elem))
                continue
            slot = [0]
            drv_status, slot_value = w.driver(self.file_type, log_number, slot)
            loop_status = drv_status
            if loop_status.byte0 != 0:
                out = Status(loop_status.code, loop_status.subcode,
                              loop_status.message)
                self.events.append(("driver_fail_move", out))
                self._teardown_file_list(file_list)
                return out
            if slot_value == 0:
                self.events.append(("slot_zero_free", elem))
                continue
            filename = w.builder1(log_number)
            self.events.append(("filename1", filename))
            b_idx = resolve_chain(w.chain_b_nodes, CHAIN_SINGLETON_B)
            b_status, handler_slot = w.chain_b_handler(b_idx)
            self.events.append(("chain_b", b_idx))
            loop_status = b_status  # status move: scratch into loop slot
            if loop_status.byte0 != 0:
                if self.file_type != 1:
                    out = Status(loop_status.code, loop_status.subcode,
                                  loop_status.message)
                    self.events.append(("chain_b_fail_move", out))
                    self._teardown_file_list(file_list)
                    return out
                # Retry arm (file type 1 only).
                filename0 = w.builder0(log_number)
                self.events.append(("filename0_retry", filename0))
                a_idx = resolve_chain(w.retry_a_nodes, CHAIN_SINGLETON_RETRY)
                ra_status = w.retry_a_handler(a_idx)
                self.events.append(("retry_a", a_idx))
                if ra_status.byte0 != 0:
                    self.events.append(("retry_a_fail", filename0))
                    out = Status(loop_status.code, loop_status.subcode,
                                  loop_status.message)
                    self._teardown_file_list(file_list)
                    return out
                b2_idx = resolve_chain(w.retry_b_nodes, CHAIN_SINGLETON_B)
                b2_status, handler_slot = w.retry_b_handler(b2_idx)
                self.events.append(("retry_b", b2_idx))
                loop_status = b2_status
                if loop_status.byte0 != 0:
                    a2_idx = resolve_chain(w.retry_a2_nodes,
                                            CHAIN_SINGLETON_RETRY)
                    ra2_status = w.retry_a2_handler(a2_idx)
                    self.events.append(("retry_a2", a2_idx))
                    if ra2_status.byte0 == 1:
                        self.events.append(("swallow", filename0))
                        loop_status = Status()
                        continue
                    self.events.append(("retry_a2_fail", filename0))
                    out = Status(loop_status.code, loop_status.subcode,
                                  loop_status.message)
                    self._teardown_file_list(file_list)
                    return out
            record = Record(log_number, self.file_type, slot_value,
                            handler_slot)
            self._append(record)
            self.events.append(("append", record))
        self.events.append(("destroy_records", len(self.records)))
        out = entry_status.copy()
        self.events.append(("loop_end_copy", out))
        self._teardown_file_list(file_list)
        return out
