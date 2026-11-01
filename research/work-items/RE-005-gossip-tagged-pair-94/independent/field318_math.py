"""Pure selector/u64/state relation; no instruction or register evaluator."""

MAX = (1 << 64) - 1
TYPE_NAME = "core::option::Option<node::gossip_rpc::GossipStatus>"


def field_relation(case_id, mode, counter, limit, wire):
    assert all(0 <= n <= MAX for n in [mode, counter, limit])
    result = {"id": case_id, "tag": None, "option_tag": None,
              "first": None, "second": None, "needed": None,
              "expected": None, "found": None, "type_name": None,
              "allowed_tags": None, "counter_after": counter,
              "counter_writes": [], "consumed": 0, "remaining": len(wire),
              "tail_hex": wire.hex(), "phase": "selector_error"}
    position = 0

    def finish(tag):
        result["tag"] = tag
        result["consumed"] = position
        result["remaining"] = len(wire) - position
        result["tail_hex"] = wire[position:].hex()
        return result

    def charge(amount):
        if (mode & 0xFFFFFFFF) != 1:
            return True
        next_value = result["counter_after"] + amount
        if next_value > MAX:
            return False
        result["counter_after"] = next_value
        result["counter_writes"].append(next_value)
        return next_value <= limit

    def integer():
        nonlocal position
        if not charge(8):
            return 2, None
        tail = wire[position:]
        if not tail:
            result["needed"] = 1
            return 0, None
        marker = tail[0]
        if marker >= 254:
            result["expected"] = 2 if len(tail) >= 9 else 3
            result["found"] = 4 if marker == 254 else 12
            position += 0 if len(tail) >= 9 else 1
            return 3, None
        if marker <= 250:
            position += 1
            return 18, marker
        total = {251: 3, 252: 5, 253: 9}[marker]
        if len(tail) < total:
            result["needed"] = total - len(tail)
            position += 1
            return 0, None
        value = int.from_bytes(tail[1:total], "little")
        position += total
        return 18, value

    if not charge(1):
        return finish(2)
    if not wire:
        result["needed"] = 1
        return finish(0)
    selector = wire[0]
    position = 1
    if selector == 0:
        result["phase"] = "none"
        result["option_tag"] = 0
        return finish(18)
    if selector != 1:
        result["found"] = selector
        result["type_name"] = TYPE_NAME
        result["allowed_tags"] = [0, 1]
        return finish(5)
    result["phase"] = "first_error"
    tag, first = integer()
    if tag != 18:
        return finish(tag)
    result["phase"] = "second_error"
    tag, second = integer()
    if tag != 18:
        return finish(tag)
    result["phase"] = "some"
    result["option_tag"] = 1
    result["first"], result["second"] = first, second
    return finish(18)
