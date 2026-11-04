"""Python model of node #115 routine 0x5d50400 (RE-001 shared copy).

The routine takes a destination pointer in rdi and a source pointer in
rsi, copies exactly 16 bytes, and then, when the copied record's
second qword is non-null, increments the dword at that target's +0x08
slot by one. The copy source is the record at (rsi) by default, or the
record at (rsi + 0x20) when the selector at (rsi + 0x10) is non-null
and the byte at selector + 0x68 is nonzero. The increment is a plain
add when the flag byte reached through the pointer held at 0x64ed290
is nonzero, and a locked add when that flag byte is zero; both add
exactly one, modulo 2**32.

A source is a dict with "base" (16 bytes), "alt" (16 bytes) and
"selector" (None, or a dict with "byte_68" 0/1). A control target is
a dict with "count" (the dword at +0x08) and any other fields, which
the routine never touches. The copied record's second qword is
modelled as the control target itself or None: copy_shared returns
(dest_bytes, ops), where ops records ("copy", "base"|"alt") and, when
a control target is present, ("add"|"lock_add", target, new_count).
"""


def copy_shared(source, control, flag_nonzero):
    """Run the 0x5d50400 behaviour; return (dest_bytes, ops)."""
    selector = source["selector"]
    if selector is not None and selector["byte_68"] != 0:
        dest = bytes(source["alt"])
        kind = "alt"
    else:
        dest = bytes(source["base"])
        kind = "base"
    ops = [("copy", kind)]
    if control is not None:
        control["count"] = (control["count"] + 1) % (1 << 32)
        ops.append(("add" if flag_nonzero else "lock_add",
                    control, control["count"]))
    return dest, ops


def make_source(base, alt, selector_byte_68=None):
    """Build a source; selector_byte_68 None means a null selector."""
    selector = None if selector_byte_68 is None else {
        "byte_68": selector_byte_68}
    return {"base": bytes(base), "alt": bytes(alt), "selector": selector}
