"""Model of node #115 Ip variant JSON writer, 0x5a2ff40 (RE-001).

The routine writes one JSON object member, {"Ip":<payload>}, into a
shared output buffer. It is a field/element writer inside larger
serializers: at the inspected call sites the caller appends JSON
punctuation ('[', ':') to the same buffer immediately before calling.

Pinned layout (see
research/work-items/RE-001-ip-variant-json-2ff40-115/):

- Output buffer: +0x00 capacity in bytes, +0x08 data pointer,
  +0x10 length in bytes. The routine reads all three fields and
  stores the length back after every append it performs.
- Context: rsi points at a context whose +0x00 word is the output
  buffer pointer. The same context pointer is forwarded to the
  payload writer; this routine reads no other context field.
- rdi is an opaque payload source, forwarded untouched to the
  payload writer; this routine never dereferences it.

Pinned behavior, reproduced exactly:

- Append order on the success path: '{', '"', the two key bytes
  "Ip" (pointer+length constant at 0x93a200, appended through the
  append-bytes helper 0x50a3510), '"', ':', the payload (appended
  by the payload writer 0x50a2ad0), and '}'.
- Before each of the five inline single-byte appends ('{', both
  quotes, ':', '}') the routine compares length with capacity
  and, only on equality, calls the grow helper 0x5963a10 with
  (rdi = buffer, edx = 1, ecx = 1, r8d = 1), reloads the length,
  and appends without re-testing capacity.
- The payload writer's status is the routine's return value,
  verbatim. A nonzero status returns immediately: the closing
  brace is not appended and the buffer keeps {"Ip": plus whatever
  partial payload the writer appended. On the success path the
  returned 0 is preserved across the closing-brace grow call
  (saved in r14 at 0x5a30099 and restored at 0x5a300a1).

The two helper callees are modeled only by their call-site
contracts; their bodies are not pinned. grow() is called exactly
when length == capacity and the pending append then proceeds, so
the model raises capacity to length + 1 (the minimum consistent
with the contract); the real growth policy is unknown.
append_bytes() appends all given bytes in order, growing as
needed by the callee's own (unpinned) mechanism. The payload is
whatever bytes the caller's payload writer appends; the model
takes the writer as a callable (value, ctx) -> status that
appends through ctx[0], mirroring the real signature.
"""

KEY = b"Ip"
KEY_ADDRESS = 0x93A200

OPEN_BRACE = 0x7B  # '{'
QUOTE = 0x22  # '"'
COLON = 0x3A  # ':'


class Buffer:
    """Growable byte buffer with the pinned layout.

    capacity/length are byte counts, mirroring +0x00/+0x10; data
    mirrors the +0x08 allocation (only data[:length] is live).
    grow_calls records the (edx, ecx, r8d) arguments of every
    grow-helper call this routine makes; append_log records the
    byte strings handed to the append-bytes helper.
    """

    def __init__(self, capacity=0, initial=b""):
        if capacity < len(initial):
            raise ValueError("capacity below initial length")
        self.capacity = capacity
        self.data = bytearray(capacity)
        self.data[: len(initial)] = initial
        self.length = len(initial)
        self.grow_calls = []
        self.append_log = []

    def grow(self, edx, ecx, r8d):
        """The grow helper 0x5963a10, modeled by its call contract.

        Called by the routine only when length == capacity; the
        pending append proceeds afterwards without a re-check, so
        capacity rises to at least length + 1. The recorded
        arguments are the pinned constants.
        """
        self.grow_calls.append((edx, ecx, r8d))
        need = self.length + 1
        if self.capacity < need:
            self.data.extend(b"\x00" * (need - self.capacity))
            self.capacity = need

    def append_bytes(self, chunk):
        """The append-bytes helper 0x50a3510, modeled by contract.

        Appends every byte in order; any growth inside the helper
        is the callee's own business and is not recorded in
        grow_calls.
        """
        chunk = bytes(chunk)
        self.append_log.append(chunk)
        end = self.length + len(chunk)
        if end > self.capacity:
            self.data.extend(b"\x00" * (end - self.capacity))
            self.capacity = end
        self.data[self.length : end] = chunk
        self.length = end

    def bytes(self):
        return bytes(self.data[: self.length])


def _append_inline(buf, byte):
    """One inline single-byte append, with the pinned growth gate:
    grow (with the constant arguments) exactly when the buffer is
    full, then write at data[length] without re-testing capacity.
    """
    if buf.length == buf.capacity:
        buf.grow(1, 1, 1)
    buf.data[buf.length] = byte
    buf.length += 1


def write_ip_variant(value, ctx, payload_writer):
    """Write {"Ip":<payload>} into ctx[0]; return the payload
    writer's status verbatim.

    value is the opaque payload source (the routine's rdi),
    forwarded untouched. ctx mirrors the rsi context: ctx[0] is
    the output Buffer. payload_writer(value, ctx) appends the
    payload through ctx[0] and returns a status word; 0 is
    success.
    """
    buf = ctx[0]
    _append_inline(buf, OPEN_BRACE)
    _append_inline(buf, QUOTE)
    buf.append_bytes(KEY)
    _append_inline(buf, QUOTE)
    _append_inline(buf, COLON)
    status = payload_writer(value, ctx)
    if status != 0:
        return status
    _append_inline(buf, 0x7D)  # '}'
    return 0
