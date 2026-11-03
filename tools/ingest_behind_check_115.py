"""Node #115 ingest-behind admission gate (0x5ebd1c0) with its status builder.

RE-001 work item. The gate is a complete behavior, not a lone-window
fragment: it consults the node's selector-inversion wrapper (0x5ebd130,
pinned by the earlier RE-001 item for that wrapper and referenced here,
not re-claimed), scans every group record except the last one for an
element whose +0x18 field is zero, and returns a Status object by
pointer: OK on the clean path, or an error Status carrying one of two
RocksDB-style ingest_behind diagnostic strings on the report paths.

Native layout (all offsets from the disassembly of work/hl-node-115.bin,
bound to provenance/artifacts.json digest a6e2897c...5301):

  gate(status_out, source, third):
    struct = source + 0x40            (a struct object)
    count  = signed32(struct + 0x650)
    link   = struct + 0x30            (a link object)
    wrapper(source, third, count - 1)  (32-bit wrap; see wrapper_value)
    if wrapper == 0:
        build_status(status_out, 4, 0, 0, BOTTOM_MSG, "")
        return status_out
    count2 = signed32(struct + 0x650)  (re-read; assumed stable)
    if count2 <= 1:
        third + 0x390 = count - 1     (first read, 32-bit)
        status_out = OK               (clean path below)
        return status_out
    array = link + 0xad8               (24-byte records, count entries)
    for record in array[0:count-1]:    (the last record is NOT scanned)
        begin, end = record + 0x00, record + 0x08  (8-byte elements)
        for element in elements(begin, end):
            if [element + 0x18] == 0:
                build_status(status_out, 4, 0, 0, UPPER_MSG, "")
                return status_out
    third + 0x390 = count - 1
    status_out = OK
    return status_out

Wrapper (0x5ebd130, restated from its own RE-001 item so this model is
self-contained; the selector itself stays an oracle because its
dispatch callee 0x5f6a820 is not modelled):

  wrapper_value(index, selector_obj, rec1, rec2, selector):
    if index == 0: return 1           (no selector call, no field read)
    return (selector(selector_obj, index, rec1, rec2) ^ 1) & 0xFFFFFFFF
  where selector_obj = link + 0x40,
        rec1 = (third + 0x20, (third + 0x28 - 8) mod 2**64),
        rec2 = (third + 0x40, (third + 0x48 - 8) mod 2**64).

Status builder (0x61cf670, the shared Status constructor; modelled in
full because the gate's observable output IS the Status contents):

  build_status(out, code, byte1, byte2, msg1, msg2):
    out.code = code & 0xFF; out.byte1 = byte1; out.byte2 = byte2
    out.word3 = 0; out.byte5 = 0
    out.message = msg1 + (": " + msg2 if msg2 else "")
    (the previous message buffer is released; the new buffer is stored
    at out + 0x08. Bytes 6-7 of the Status are written by NEITHER the
    clean path nor the builder, so they are outside this model.)

Assumptions recorded explicitly:
  * The count at struct + 0x650 does not change between the gate's two
    reads (no intervening write to it exists in the gate or wrapper).
  * The caller supplies at least count - 1 records; a shorter array
    would read out of bounds natively and is rejected here.
  * Element pointers are non-null; a null element would fault natively
    and is rejected here.
  * The selector oracle returns a 32-bit result; the gate's 0/1
    contract is the usual case and the xor is applied in full.

Out of contract: negative counts take the same unsigned branches as
the native code only through the selector oracle; the model requires
count to be a signed 32-bit value and otherwise follows the native
control flow exactly.
"""

BOTTOM_MSG = "Can't ingest_behind file as it doesn't fit at the bottommost level!"
UPPER_MSG = (
    "Can't ingest_behind file as despite allow_ingest_behind=true "
    "there are files with 0 seqno in database at upper levels!"
)

MASK64 = (1 << 64) - 1
MASK32 = (1 << 32) - 1


def wrap32(value):
    """Wrap an integer to the signed 32-bit range."""
    value &= MASK32
    return value - (1 << 32) if value >= (1 << 31) else value


def _require_qword(value, name):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("%s must be an integer qword" % name)
    if value < 0 or value > MASK64:
        raise ValueError("%s out of qword range" % name)
    return value


def _require_int32(value, name):
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("%s must be an integer" % name)
    if value < -(1 << 31) or value > (1 << 31) - 1:
        raise ValueError("%s out of signed 32-bit range" % name)
    return value


def build_status(out, code, byte1, byte2, msg1, msg2):
    """Model of the Status builder at 0x61cf670.

    ``out`` is a dict representing the 16-byte Status object; it is
    mutated in place and returned. ``msg1`` and ``msg2`` are the two
    slices (data, length) collapsed to plain strings here: the native
    code concatenates them with ": " only when the second slice is
    non-empty, and stores a fresh NUL-terminated copy.
    """
    if not isinstance(msg1, str) or not isinstance(msg2, str):
        raise ValueError("status messages must be strings")
    out["code"] = code & 0xFF
    out["byte1"] = byte1 & 0xFF
    out["byte2"] = byte2 & 0xFF
    out["word3"] = 0
    out["byte5"] = 0
    out["message"] = msg1 + (": " + msg2 if msg2 else "")
    return out


def clean_status(out):
    """Model of the gate's clean path: the written Status bytes are 0.

    Bytes 6-7 are untouched by the native clean path, so they are not
    part of the returned record.
    """
    out["code"] = 0
    out["byte1"] = 0
    out["byte2"] = 0
    out["word3"] = 0
    out["byte5"] = 0
    out["message"] = None
    return out


def wrapper_value(index, selector_obj, rec1, rec2, selector):
    """Model of the selector-inversion wrapper at 0x5ebd130.

    ``index`` is the 32-bit value the gate passes (count - 1).
    ``selector`` is an oracle callable taking
    (selector_obj, index, rec1, rec2) and returning a 32-bit result.
    """
    index = _require_int32(index, "index")
    if index == 0:
        return 1
    result = selector(selector_obj, index, rec1, rec2)
    if not isinstance(result, int) or isinstance(result, bool):
        raise ValueError("selector oracle must return an integer")
    return (result & MASK32) ^ 1


def check_ingest_behind(source, third, selector, status):
    """Model of the gate at 0x5ebd1c0. Returns the mutated ``status``.

    ``source`` is {"struct40": {"count": int32, "link": link}} where
    ``link`` is {"selector": opaque, "array": [records]} and each
    record is a list of elements; each element is the integer value of
    its +0x18 field, or None for a null element pointer (rejected).
    ``third`` is {"f20": int, "f28": int, "f40": int, "f48": int,
    "f390": int or None}; the f390 field is set only on the clean
    path. ``selector`` is the oracle callable from wrapper_value.
    """
    struct = source["struct40"]
    count = _require_int32(struct["count"], "count")
    link = struct["link"]
    index = wrap32(count - 1)
    rec1 = (_require_qword(third["f20"], "third+0x20"),
            (_require_qword(third["f28"], "third+0x28") - 8) & MASK64)
    rec2 = (_require_qword(third["f40"], "third+0x40"),
            (_require_qword(third["f48"], "third+0x48") - 8) & MASK64)
    wrapped = wrapper_value(index, link["selector"], rec1, rec2, selector)
    if wrapped == 0:
        return build_status(status, 4, 0, 0, BOTTOM_MSG, "")
    # Native re-read of the count; assumed stable (see module notes).
    count2 = _require_int32(struct["count"], "count")
    if count2 <= 1:
        third["f390"] = index
        return clean_status(status)
    array = link["array"]
    if len(array) < count - 1:
        raise ValueError("record array shorter than count - 1")
    for record in array[:count - 1]:
        for element in record:
            if element is None:
                raise ValueError("null element pointer")
            if not isinstance(element, int) or isinstance(element, bool):
                raise ValueError("element +0x18 field must be an integer")
            if element == 0:
                return build_status(status, 4, 0, 0, UPPER_MSG, "")
    third["f390"] = index
    return clean_status(status)
