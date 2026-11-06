"""Model of node #115's stats version-key fetch and its produce dispatch.

Reconstruction of the behavior pinned by
research/work-items/RE-001-stats-version-fetch-115/ (RE-001):

  caller 0x5e61ad0 (persistent-stats column-family open,
  db_impl_open.cc:744)
    -> fetch 0x606e3a0 (mode 1: format-version key, mode 2:
       compatible-version key; mode > 2 is InvalidArgument)
    -> produce dispatch: source vtable slot 0xe8, compared
       against the GOT canonical 0x5d33a90 (default produce)
       - custom slot: called directly with the value string
       - default slot: slot 0xf0 is called with a replacement
         view, a cleanup chain and an aux bundle
    -> default produce 0x5d33a90 (chases the +0x8 source chain
       for the first non-canonical slot 0xf0)
    -> forward produce 0x5d2d0e0 (canonical slot 0xf0: calls
       *(source+0x8)'s slot 0xf0)
    -> result: value decimal-parsed into *out_u64 with an OK
       Status, else NotFound with the composed message

The produce callees are virtual, so the model takes the source
side as injectable objects (FakeSource in the tests) and pins
everything else from the binary: the mode table, the dispatch
rule, the chain chase, the aux replace, the decimal parse, the
Status builder composition (first view plus ": " plus the second
view when it is non-empty), the state-init stores and the
cleanup-chain layout. The caller's Status::ToString helper
0x61cfed0 is referenced, not mapped: only the code names this
flow can produce (OK, NotFound, InvalidArgument) are pinned.

Status is the 16-byte layout pinned by PR #3202: code at +0x00,
subcode at +0x01, builder-arg byte at +0x02, message pointer at
+0x08. Code 1 is NotFound, code 4 is InvalidArgument.
"""

FORMAT_VERSION_KEY = b"__persistent_stats_format_version__"
COMPATIBLE_VERSION_KEY = b"__persistent_stats_compatible_version__"
NOT_FOUND_PREFIX = b"Persistent stats version key "
NOT_FOUND_SUFFIX = b" not found."
INVALID_MODE_MESSAGE = b"Invalid stats version key type provided"
CALLER_LOG_FORMAT = (
    b"[%s:744] Recreating persistent stats column family since "
    b"reading persistent stats version key failed. "
    b"Format key: %s, compatible key: %s")
CALLER_LOG_FILE = b"db/db_impl/db_impl_open.cc"

FETCH_ADDR = 0x606E3A0
CALLER_ADDR = 0x5E61AD0
DEFAULT_PRODUCE_ADDR = 0x5D33A90
FORWARD_PRODUCE_ADDR = 0x5D2D0E0
CHAIN_INIT_ADDR = 0x61BD0C0
CHAIN_DTOR_ADDR = 0x61BD0E0
GOT_PRODUCE_E8 = 0x64ED288
GOT_PRODUCE_F0 = 0x64ED070
CANONICAL_PRODUCE_E8 = 0x5D33A90
CANONICAL_PRODUCE_F0 = 0x5D2D0E0
SLOT_E8_VTABLES = [0x64C82C0, 0x64C9368, 0x64CB0E0,
                   0x64CB5C0, 0x64CBBC0, 0x64D97D0]
SLOT_F0_VTABLES = [0x64C82C0]
MAX_U64 = (1 << 64) - 1

OK = 0
NOT_FOUND = 1
INVALID_ARGUMENT = 4

_SUFFIX_SHIFT = {b"K": 10, b"M": 20, b"G": 30, b"T": 40}


class Status:
    """The 16-byte Status: code, subcode, message (or None)."""

    def __init__(self, code=OK, subcode=0, message=None):
        self.code = code
        self.subcode = subcode
        self.message = message

    def is_ok(self):
        return self.code == OK

    def __repr__(self):
        return "Status(%d, %d, %r)" % (self.code, self.subcode,
                                       self.message)


def build_status_message(view1, view2):
    """The Status builder 0x61cf670 composition: view1, plus
    ": " plus view2 when the second view is non-empty."""
    if view2:
        return view1 + b": " + view2
    return view1


def not_found_message(key):
    """The fetch's NotFound message: prefix + key + suffix as
    the first view, with the key as the builder's second view."""
    return build_status_message(
        NOT_FOUND_PREFIX + key + NOT_FOUND_SUFFIX, key)


def select_key(mode):
    """The mode table: 0 leaves the key empty, 1 selects the
    format-version key, 2 the compatible-version key. Returns
    (key, None) or (None, InvalidArgument Status) for mode > 2."""
    if mode == 0:
        return b"", None
    if mode == 1:
        return FORMAT_VERSION_KEY, None
    if mode == 2:
        return COMPATIBLE_VERSION_KEY, None
    return None, Status(INVALID_ARGUMENT, 0, INVALID_MODE_MESSAGE)


def produce_path(slot_e8):
    """The dispatch rule: the source's slot 0xe8 compared against
    the GOT canonical 0x5d33a90."""
    if slot_e8 == CANONICAL_PRODUCE_E8:
        return "default"
    return "custom"


def parse_u64(text):
    """The decimal parser 0x61d1540: strtoull base 10 over the
    string (leading whitespace skipped, optional sign), then one
    trailing K/M/G/T suffix shifting left 10/20/30/40. Raises
    ValueError on no digits (invalid_argument) and OverflowError
    on overflow (out_of_range); a leading '-' wraps mod 2**64
    the way strtoull negates."""
    if isinstance(text, str):
        text = text.encode()
    i = 0
    while i < len(text) and text[i:i + 1] in b" \t\n\v\f\r":
        i += 1
    negative = False
    if i < len(text) and text[i:i + 1] in (b"+", b"-"):
        negative = text[i:i + 1] == b"-"
        i += 1
    start = i
    value = 0
    while i < len(text) and 0x30 <= text[i] <= 0x39:
        value = value * 10 + (text[i] - 0x30)
        if value > MAX_U64:
            raise OverflowError("out_of_range")
        i += 1
    if i == start:
        raise ValueError("invalid_argument")
    if negative:
        value = (-value) & MAX_U64
    if i < len(text):
        suffix = text[i:i + 1]
        if suffix not in _SUFFIX_SHIFT:
            raise ValueError("invalid_argument")
        value = value << _SUFFIX_SHIFT[suffix]
        if value > MAX_U64:
            raise OverflowError("out_of_range")
        i += 1
    if i != len(text):
        raise ValueError("invalid_argument")
    return value


def state_init_bytes():
    """The 0x90-byte produce state as 0x60b21f0 leaves it: all
    zero except +0x2c = 0x101, +0x78 = -1, +0x84 = 4,
    +0x88 = 0x100. The fetch then writes byte 1 at +0x2c,
    which is already the low byte of 0x101."""
    state = bytearray(0x90)
    state[0x2C:0x34] = (0x101).to_bytes(8, "little")
    state[0x78:0x80] = ((1 << 64) - 1).to_bytes(8, "little")
    state[0x84:0x88] = (4).to_bytes(4, "little")
    state[0x88:0x8A] = (0x100).to_bytes(2, "little")
    return bytes(state)


class ProduceResult:
    """What a produce call leaves behind: the out flag (nonzero
    means no value was produced), the value string, the aux flag
    and the replacement view the 0xf0 path may carry."""

    def __init__(self, flag=0, value=b"", aux_flag=0, replacement=b""):
        self.flag = flag
        self.value = value
        self.aux_flag = aux_flag
        self.replacement = replacement


def apply_produce_result(result):
    """The fetch's result protocol. Returns (Status, out_u64 or
    None). A parse failure raises, as in the binary (no handler
    is pinned in the fetch)."""
    if result.flag != 0:
        return Status(NOT_FOUND, 0, None), None
    value = result.value
    if result.aux_flag != 0:
        value = result.replacement
    if len(value) == 0:
        return Status(NOT_FOUND, 0, None), None
    return Status(OK, 0, None), parse_u64(value)


def apply_produce_result_with_message(result, key):
    """apply_produce_result with the NotFound message composed
    for the fetched key."""
    status, out = apply_produce_result(result)
    if status.code == NOT_FOUND:
        status = Status(NOT_FOUND, 0, not_found_message(key))
    return status, out


class ChainNode:
    """One cleanup-chain node: {callback +0x00, arg1 +0x08,
    arg2 +0x10, next +0x18} (32 bytes)."""

    def __init__(self, callback=None, arg1=None, arg2=None,
                 next_node=None):
        self.callback = callback
        self.arg1 = arg1
        self.arg2 = arg2
        self.next = next_node


def chain_init():
    """The chain initializer 0x61bd0c0: callback 0, next 0."""
    return ChainNode()


def chain_destroy(head):
    """The chain destructor 0x61bd0e0: return at once on a null
    callback; otherwise call the callback with (arg1, arg2),
    then walk the next list calling each node's callback and
    freeing each node."""
    node = head
    if node.callback is None:
        return
    while node is not None:
        if node.callback is not None:
            node.callback(node.arg1, node.arg2)
        node = node.next


def call_slot_f0(source):
    """Call a source's slot 0xf0. When the slot is the canonical
    forwarder 0x5d2d0e0 it calls *(source+0x8)'s slot 0xf0 with
    the same arguments (one hop forward)."""
    if source.slot_f0 == CANONICAL_PRODUCE_F0:
        return call_slot_f0(source.next_source)
    return source.slot_f0()


def default_produce(source):
    """The default produce 0x5d33a90: compare the slot 0xf0 of
    the source, then *(source+0x8), then *(that+0x8) against the
    canonical 0x5d2d0e0; call the first non-canonical slot; if
    all three are canonical, call the fourth hop's slot 0xf0
    unconditionally. Afterwards, when the out flag is 0 and the
    aux flag is nonzero, the value is replaced from the aux
    view (applied by the caller through apply_produce_result)."""
    hop = source
    for _ in range(3):
        if hop.slot_f0 != CANONICAL_PRODUCE_F0:
            return call_slot_f0(hop)
        hop = hop.next_source
    return call_slot_f0(hop)


def fetch(mode, source):
    """The fetch 0x606e3a0 end to end. `source` carries `bound`
    (the getter result), `slot_e8` (a callable returning a
    ProduceResult, or the canonical 0x5d33a90) and `next_source`
    (the +0x8 chain for the default produce). Returns
    (Status, out_u64 or None)."""
    key, error = select_key(mode)
    if error is not None:
        return error, None
    if produce_path(source.slot_e8) == "custom":
        result = source.slot_e8()
    else:
        result = default_produce(source)
    return apply_produce_result_with_message(result, key)


def caller_gate(status1, status2):
    """The caller's both-OK gate: both Status codes ORed; both
    zero proceeds."""
    return status1.code == OK and status2.code == OK


def status_to_string(status):
    """The Status::ToString helper 0x61cfed0 as used by the caller:
    the code name from its table, plus ": " plus the message when
    the Status carries one. Only the codes this flow can produce
    are pinned (OK, NotFound, InvalidArgument); other codes are
    unmapped here."""
    names = {OK: b"OK", NOT_FOUND: b"NotFound",
             INVALID_ARGUMENT: b"InvalidArgument"}
    if status.code not in names:
        raise ValueError("unmapped status code %d" % status.code)
    if status.is_ok():
        return names[status.code]
    return names[status.code] + b": " + (status.message or b"")


def caller_log_message(format_status_text, compatible_status_text):
    """The caller's error-log line: the format at 0x95e370 with
    the file at 0x960600 and the two Statuses' ToString results
    (built with 0x61cfed0)."""
    return (CALLER_LOG_FORMAT
            % (CALLER_LOG_FILE, format_status_text,
               compatible_status_text))


def caller_fetch_both(source):
    """The caller's version fetch: mode 1 then mode 2, the
    both-OK gate, and the error-log message on failure. Returns
    (ok, value1, value2, log_or_None)."""
    status1, value1 = fetch(1, source)
    status2, value2 = fetch(2, source)
    if caller_gate(status1, status2):
        return True, value1, value2, None
    return False, value1, value2, caller_log_message(
        status_to_string(status1), status_to_string(status2))
