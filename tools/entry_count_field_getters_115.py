"""Node #115 small getter run 0x5eeb150..0x5eeb213: entry-range count and
plain field projections.

RE-001 work item. Five whole getters, all returning 1 unconditionally with
no null check anywhere:

A. count 0x5eeb150 (outer in rdi, out in rsi): member = [outer + 0x788],
   sub = [member + 0x30]; *out = ([sub + 0xb20] - [sub + 0xb18]) >> 4
   (arithmetic shift on the wrapped 64-bit difference). This is the entry
   count of the same 16-byte entry range whose sums and report the twin
   entry-sum getters of #2307 and the blob-file report of #2313 walk.

B. signed field 0x5eeb180 (obj in rdx, out in rsi, rdi ignored):
   *out = sign_extend32([obj + 0x1438]) via movslq.

C. field 0x5eeb1a0 (obj in rdi, out in rsi): *out = [obj + 0x770].

D. field 0x5eeb1c0 (obj in rdx, out in rsi, rdi ignored):
   *out = [obj + 0x1228].

E. guarded field 0x5eeb1e0 (obj in rdx, out in rsi, rdi ignored):
   ptr = [obj + 0x1200]; *out = 0 when ptr == obj + 0x11e0 (the empty
   sentinel arm, no dereference), else *out = [ptr + 0x30].

The model takes plain data. Missing keys raise KeyError, mirroring the
native code's unchecked dereferences; the guarded getter's sentinel arm
deliberately needs no field30, mirroring the missing dereference there.
"""

MASK = (1 << 64) - 1
SIGN64 = 1 << 63


def _wrap64(value):
    return value & MASK


def _signed64(value):
    value &= MASK
    return value - (1 << 64) if value & SIGN64 else value


def _sign_extend32(value):
    value &= 0xFFFFFFFF
    return value - (1 << 32) if value & 0x80000000 else value


def count_getter(member788):
    """Getter A: (1, entry count) for the [sub + 0xb18, sub + 0xb20) range.

    member788 is the [outer + 0x788] member dict {"sub30": {"begin": int,
    "end": int}}. The difference wraps to 64 bits and the shift is
    arithmetic, so a malformed end < begin range yields a negative count
    exactly as sar does.
    """
    sub = member788["sub30"]
    diff = _signed64(sub["end"] - sub["begin"])
    return 1, diff >> 4


def signed_field_getter(obj):
    """Getter B: (1, sign-extended [obj + 0x1438])."""
    return 1, _sign_extend32(obj["f1438"])


def field_770_getter(obj):
    """Getter C: (1, [obj + 0x770])."""
    return 1, _wrap64(obj["f770"])


def field_1228_getter(obj):
    """Getter D: (1, [obj + 0x1228])."""
    return 1, _wrap64(obj["f1228"])


def guarded_field_getter(obj):
    """Getter E: (1, 0) on the sentinel arm, else (1, [ptr + 0x30]).

    obj is {"ptr": int, "sentinel": int, "field30": int}; field30 is only
    read on the non-sentinel arm, so the sentinel arm passes with
    field30 absent, exactly as the native code skips the dereference.
    """
    if obj["ptr"] == obj["sentinel"]:
        return 1, 0
    return 1, _wrap64(obj["field30"])


if __name__ == "__main__":
    assert count_getter({"sub30": {"begin": 0x1000, "end": 0x1050}}) == (1, 5)
    assert signed_field_getter({"f1438": 0xFFFFFFFF}) == (1, -1)
    assert field_770_getter({"f770": 42}) == (1, 42)
    assert field_1228_getter({"f1228": 42}) == (1, 42)
    assert guarded_field_getter({"ptr": 0x2000, "sentinel": 0x2000}) == (1, 0)
    assert guarded_field_getter(
        {"ptr": 0x3000, "sentinel": 0x2000, "field30": 7}) == (1, 7)
    print("entry_count_field_getters_115 smoke OK")
