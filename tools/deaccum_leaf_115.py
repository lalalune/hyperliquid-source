"""Python model of node #115's gated de-accumulation leaf at 0x5f6b620.

RE-001 work item: research/work-items/RE-001-deaccum-leaf-115/.
The leaf takes (base, element) in (rdi, rsi) and returns void. All
arithmetic below is wrapping 64-bit, matching the native code: the
+0xb5 flag byte gates the whole update, and the three counter
updates exactly reverse three of the accumulation leaf's updates.
"""

MASK64 = (1 << 64) - 1


def _u64(value):
    return value & MASK64


def deaccumulate(base, element):
    """Apply the leaf to base counters for one element.

    base: a mapping with the counter fields "fb0", "fb8" and "fc0"
    (the qwords at base+0xfb0, base+0xfb8 and base+0xfc0).
    element: a mapping with "b5" (the flag byte at element+0xb5)
    and "80" and "88" (the qwords at element+0x80 and element+0x88).
    Returns True when the flag gate passed and the counters were
    updated, False when the flag byte was zero and nothing changed.
    Raises KeyError when a required field is absent, so a caller
    cannot silently model a partially known object.
    """
    for field in ("fb0", "fb8", "fc0"):
        if field not in base:
            raise KeyError("base is missing %s" % field)
    for field in ("b5", "80", "88"):
        if field not in element:
            raise KeyError("element is missing %s" % field)
    if (element["b5"] & 0xFF) == 0:
        return False
    base["fb0"] = _u64(base["fb0"] + element["88"] - element["80"])
    base["fc0"] = _u64(base["fc0"] - 1)
    base["fb8"] = _u64(base["fb8"] - element["88"])
    return True


def deaccumulate_from_obj(obj, element):
    """Apply the leaf using caller terms (base = obj+0x40).

    obj must carry "ff0", "ff8" and "1000" (the counters at obj+0xff0,
    obj+0xff8 and obj+0x1000, following the accumulation-leaf item's
    convention). The element mapping is the same as deaccumulate's.
    Returns True when the update applied, False on a zero flag byte.
    """
    for field in ("ff0", "ff8", "1000"):
        if field not in obj:
            raise KeyError("obj is missing %s" % field)
    base = {"fb0": obj["ff0"], "fb8": obj["ff8"], "fc0": obj["1000"]}
    applied = deaccumulate(base, element)
    if applied:
        obj["ff0"], obj["ff8"], obj["1000"] = (
            base["fb0"], base["fb8"], base["fc0"])
    return applied
