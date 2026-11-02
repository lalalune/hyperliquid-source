"""Mathematical composition of the admitted prefix, vector and UTF-8 relations."""

from utf8_math import utf8_relation

MAX = (1 << 64) - 1


def wire_relation(case_id, mode, counter, limit, wire):
    """Chosen logical normal-allocation projection, without pointer/ABI bytes."""
    assert all(0 <= n <= MAX for n in [mode, counter, limit])
    assert len(wire) <= (1 << 63) - 1
    result = {"id": case_id, "tag": None, "needed": None, "expected": None,
              "found": None, "valid_up_to": None, "error_len": None,
              "data_hex": None, "release_request_length": None,
              "counter_after": counter, "counter_writes": [],
              "consumed": 0, "remaining": len(wire), "tail_hex": wire.hex(),
              "phase": "header_error"}

    def counter_store(value):
        result["counter_after"] = value
        result["counter_writes"].append(value)

    def finish(tag, consumed):
        result["tag"] = tag
        result["consumed"] = consumed
        result["remaining"] = len(wire) - consumed
        result["tail_hex"] = wire[consumed:].hex()
        return result

    # Established native u64 outer/Reader theorem, used as separate context.
    if mode & 0xFFFFFFFF == 1:
        charged = counter + 8
        if charged > MAX:
            return finish(2, 0)
        counter_store(charged)
        if charged > limit:
            return finish(2, 0)
    if not wire:
        result["needed"] = 1
        return finish(0, 0)
    marker = wire[0]
    fast = len(wire) >= 9
    if marker >= 254:
        result["expected"] = 2 if fast else 3
        result["found"] = 4 if marker == 254 else 12
        return finish(3, 0 if fast else 1)
    if marker <= 250:
        length, prefix = marker, 1
    else:
        prefix = {251: 3, 252: 5, 253: 9}[marker]
        if len(wire) < prefix:
            result["needed"] = prefix - len(wire)
            return finish(0, 1)
        length = int.from_bytes(wire[1:prefix], "little")
    result["phase"] = "payload_budget"
    if mode != 0:
        charged = result["counter_after"] + length
        if charged > MAX:
            return finish(2, prefix)
        counter_store(charged)
        if charged > limit:
            return finish(2, prefix)
    if length > len(wire) - prefix:
        result["phase"] = "payload_short"
        return finish(1, prefix)
    # Availability plus the admitted slice bound proves length <= isize::MAX.
    payload = wire[prefix:prefix + length]
    issue = utf8_relation(payload)
    if issue is not None:
        result["phase"] = "invalid_utf8"
        result["valid_up_to"], result["error_len"] = issue
        result["release_request_length"] = length
        return finish(6, prefix + length)
    result["phase"] = "ok"
    result["data_hex"] = payload.hex()
    return finish(18, prefix + length)
