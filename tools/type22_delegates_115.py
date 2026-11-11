"""Model of the RE-001 type-22 apply delegate and serializer helper (node #115).

Pinned against node #115, SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.

Evidence packet: research/work-items/RE-001-type22-delegates-115/
(whole-function objdump excerpts + semantic records.json + verify.py).

Pinned semantics
----------------
* 0x609a740 (type-22 apply delegate, sole caller 0x609b80f inside
  apply-created 0x609b700): resolves the target field from the record
  offset (+0x00) and flags (+0xb0), copies the 0x50-byte ConfigOptions,
  then dispatches on record flags bit 0x100 and ConfigOptions+0x04.
* 0x60971c0 (serializer helper): calls the object's vtable slot 12
  (0x609de80) and braces the result when it contains '='.
* 0x609de80 (vtable slot 12): emits
  [rcx-arg] + "id" + "=" + id + [ConfigOptions+0x08] + [nested options]
  when ConfigOptions+0x28 != 1, the id is non-empty, and the nested
  options are non-empty; otherwise the bare id.
* 0x61d1390 ends_with, 0x61d13e0 starts_with: the string predicates
  the delegate uses for the ".id" suffix and key comparisons.
* Status: code 0 = kOk; code 4 = kInvalidArgument with the prefix
  "Option not changeable: " (literal 0x4341c2).
"""
from __future__ import annotations

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)
DEREF_FLAG_MASK = 0x200 | 0x400 | 0x800
FLAG_0X100 = 0x100
NOT_CHANGEABLE_PREFIX = "Option not changeable: "

# Pinned addresses (node #115).
DELEGATE = 0x609A740
SERIALIZER_HELPER = 0x60971C0
SLOT12 = 0x609DE80
GET_ID = 0x5D32A30
SLOT10_CORE = 0x60986B0
ENDS_WITH = 0x61D1390
STRING_COMPARE = 0x61D13E0


def resolve_field(store, base, offset, flags):
    """Resolve the delegate's target: base + record offset, deref once when
    any of record flags 0x200/0x400/0x800 is set (0x609a740, 0x609a7a6-0x609a7b7).

    ``store`` maps a field address to the pointer it holds; ``base`` None
    (null options-base) yields a null target. When no deref bit is set the
    field address itself is the target.
    """
    if base is None or base == 0:
        return None
    signed_offset = ((offset & 0xffffffff) ^ 0x80000000) - 0x80000000
    addr = (base + signed_offset) & ((1 << 64) - 1)
    if flags & DEREF_FLAG_MASK:
        return store[addr]
    return addr


def ends_with(haystack, suffix):
    """0x61d1390: haystack.size() >= suffix.size() and the tail bytes match."""
    if len(haystack) < len(suffix):
        return False
    return haystack.endswith(suffix)


def string_compare(a, b):
    """Historical label for 0x61d13e0, a boolean starts-with predicate.

    It compares the shorter byte span, then accepts only when b fits in a.
    Text inputs denote their UTF-8 bytes; bytes inputs preserve arbitrary data.
    """
    a_bytes = a.encode("utf-8") if isinstance(a, str) else bytes(a)
    b_bytes = b.encode("utf-8") if isinstance(b, str) else bytes(b)
    return a_bytes.startswith(b_bytes)


def slot12_emit(rcx_arg, obj_id, delimiter, nested_options, config_plus28):
    """0x609de80: the shared nested-Configurable serializer.

    ``delimiter`` is the ConfigOptions+0x08 string; ``nested_options`` is
    the 0x60985e0 output. The long emission happens only when
    config+0x28 != 1, the id is non-empty, and the nested options are
    non-empty; otherwise the bare id is returned.
    """
    if config_plus28 != 1 and obj_id and nested_options:
        return rcx_arg + "id" + "=" + obj_id + delimiter + nested_options
    return obj_id


def brace_wrap(options):
    """0x60971c0: empty output or no '=' -> verbatim; otherwise
    '{' + output + '}'."""
    if not options or "=" not in options:
        return options
    return "{" + options + "}"


def status_ok():
    """0x609a740 @ 0x609aacf: Status code 0, empty message."""
    return (0, "")


def status_not_changeable(name):
    """0x609a740 @ 0x609ae22 / 0x609b217: Status ctor 0x61cf670, code 4
    (kInvalidArgument), message prefix + the option name."""
    return (4, NOT_CHANGEABLE_PREFIX + name)


def delegate_decision(*, flags, config_plus4, name, remaining_key, value,
                      target_id, target_is_null=False):
    """Select a local outcome or unresolved callee boundary in 0x609a740.

    The resolved field target controls the null test. Virtual dispatch assumes
    valid receiver objects and normal returns. Callee outcomes remain delegated.
    """
    if flags & FLAG_0X100 or config_plus4 == 0:
        if remaining_key == name or remaining_key == "id" or ends_with(name, ".id"):
            return ("configure_slot10", (name, remaining_key, value))
        if not value:
            return ("ok", status_ok())
        if target_is_null or not string_compare(remaining_key, target_id + "."):
            return ("configure_slot10", (name, remaining_key, value))
        if "=" in value:
            return ("set_via_equals", (name, value))
        return ("forward_no_equals", (name, value))
    if target_is_null:
        if not value:
            return ("ok", status_ok())
        return ("error", status_not_changeable(name))
    if ends_with(name, ".id"):
        if value == target_id:
            return ("ok", status_ok())
        return ("error", status_not_changeable(name))
    if remaining_key == name or remaining_key == "id":
        return ("configure_by_id", (name, value))
    return ("forward_no_equals", (name, value))
