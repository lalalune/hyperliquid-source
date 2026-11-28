"""Encode ordinary named order results for the offline worker response Hash."""

import re

import msgpack


QUANTITY = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[0-9]*[1-9]))?")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def ordinary_status(status, fixed_hex):
    if isinstance(status, str) and status in ("waitingForFill", "waitingForTrigger"):
        return status
    require(type(status) is dict and len(status) == 1, "expected a named order status")
    label, body = next(iter(status.items()))
    if label == "error":
        require(type(body) is str and len(body.encode("utf-8")) <= 255, "expected short UTF-8 order error")
        return {label: body}
    require(label in ("filled", "resting") and type(body) is dict, "unsupported order status")
    quantities = ("totalSz", "avgPx") if label == "filled" else ()
    required = {"oid", *quantities}
    require(set(body) in (required, required | {"cloid"}), "wrong nested order status fields")
    normalized = {}
    for name in quantities:
        value = body[name]
        require(type(value) is str and len(value) <= 255 and QUANTITY.fullmatch(value) is not None,
                f"{name} must be normalized nonnegative fixed-point text")
        normalized[name] = value
    order_id = body["oid"]
    require(type(order_id) is int and 0 <= order_id < 1 << 64, "oid must be an unsigned 64-bit integer")
    normalized["oid"] = order_id
    if "cloid" in body:
        fixed_hex(body["cloid"], 16)
        normalized["cloid"] = body["cloid"]
    return {label: normalized}


def order_entry(entry, prior):
    require(type(entry) is dict and set(entry) == {"user", "res"}, "expected user and res")
    result = entry["res"]
    response = result.get("response") if isinstance(result, dict) else None
    if not (isinstance(response, dict) and response.get("type") == "order"):
        return prior.encode_entry(entry)
    require(set(result) == {"status", "response"} and result["status"] == "ok"
            and set(response) == {"type", "data"}, "wrong order result")
    data = response["data"]
    require(type(data) is dict and set(data) == {"statuses"} and type(data["statuses"]) is list,
            "expected order statuses array")
    user = entry["user"]
    if user is not None:
        prior.fixed_hex(user, 20)
    statuses = [ordinary_status(status, prior.fixed_hex) for status in data["statuses"]]
    return msgpack.packb({"user": user, "res": {
        "status": "ok", "response": {"type": "order", "data": {"statuses": statuses}},
    }}, use_bin_type=True)


def encode_rows(rows, prior):
    require(type(rows) is list, "expected ordered Full outcome rows")
    output = bytearray(prior.array_header(len(rows)))
    entries = 0
    for group, row in enumerate(rows):
        require(type(row) is list and len(row) == 2 and type(row[1]) is list,
                f"wrong Full result group {group}")
        output += b"\x92\xd9\x42" + prior.fixed_hex(row[0], 32)
        output += prior.array_header(len(row[1]))
        for position, entry in enumerate(row[1]):
            try:
                output += order_entry(entry, prior)
            except ValueError as error:
                raise ValueError(f"group {group}, position {position}: {error}") from error
            entries += 1
    return bytes(output), entries


def compare(archive, full, prior):
    require(type(archive["height"]) is int and type(full["height"]) is int
            and 0 <= archive["height"] < 1 << 64 and archive["height"] == full["height"],
            "archive and Full observation must have the same exact height")
    require(type(archive["resps"]) is dict and set(archive["resps"]) == {"Hash"}, "expected archive Hash")
    require(type(full["resps"]) is dict and set(full["resps"]) == {"Full"}, "expected local Full")
    expected = prior.fixed_hex(archive["resps"]["Hash"], 32).decode("ascii")
    rows = full["resps"]["Full"]
    raw, entries = encode_rows(rows, prior)
    return prior.Comparison(expected, "0x" + prior.keccak256(raw).hex(), len(rows), entries)
