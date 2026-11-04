"""Model of node #115 routine 0x5d5ab60: libstdc++ string concatenation
of two string rvalues (operator+ for basic_string&&, basic_string&&).

Representation: a string object is a dict with keys
  bytes    -- the character bytes (without the terminating NUL)
  capacity -- heap capacity when not SSO; ignored when SSO
  sso      -- True when the short-string form is in use (capacity 15)

Layout pinned from the routine: data pointer at +0x00, size at +0x08,
SSO buffer / heap capacity at +0x10; SSO capacity is 15.

Path choice, exactly as the branch structure pins it:
  total = len(lhs) + len(rhs)
  if total > capacity(lhs) and total <= capacity(rhs):
      path = "insert"  (rhs.insert(0, lhs) via _M_replace, then move)
  else:
      path = "append"  (lhs.append(rhs) via _M_append, then steal lhs)
  On the append path, total > 0x3fffffffffffffff raises LengthError
  with the routine's own message, "basic_string::append".
  On the insert path the routine performs no such check itself;
  length handling there lives inside _M_replace and is not modelled.

After-states on the append path: a heap lhs is stolen into the
result and reset to an empty SSO string; an SSO lhs keeps its
appended bytes (the result is a byte copy, so no double ownership
arises). On the insert path the rhs is move-constructed into the
result and is left moved-from; the lhs is untouched.
In every path the result is SSO exactly when total <= 15.
"""

MAX_SIZE = 0x3FFFFFFFFFFFFFFF


class LengthError(ValueError):
    """Mirrors the routine's __throw_length_error on the append path."""
SSO_CAPACITY = 15


def capacity(string):
    return SSO_CAPACITY if string["sso"] else string["capacity"]


def make_string(data, capacity=None, sso=None):
    if sso is None:
        sso = len(data) <= SSO_CAPACITY
    return {"bytes": bytes(data), "capacity": capacity or 0, "sso": sso}


def empty_sso():
    return {"bytes": b"", "capacity": 0, "sso": True}


def concat(lhs, rhs):
    """Return (result, path, lhs_after, rhs_after).

    rhs_after is the string object, or the string "moved_from" on the
    insert path, where the routine move-constructs the result out of
    rhs and leaves rhs's fields unpinned.
    """
    total = len(lhs["bytes"]) + len(rhs["bytes"])
    result_bytes = lhs["bytes"] + rhs["bytes"]
    result = {"bytes": result_bytes,
              "capacity": 0 if total <= SSO_CAPACITY else None,
              "sso": total <= SSO_CAPACITY}
    if total > capacity(lhs) and total <= capacity(rhs):
        return result, "insert", dict(lhs), "moved_from"
    if total > MAX_SIZE:
        raise LengthError("basic_string::append")
    if lhs["sso"] and total <= SSO_CAPACITY:
        lhs_after = {"bytes": result_bytes, "capacity": 0, "sso": True}
    elif lhs["sso"]:
        lhs_after = empty_sso()
    else:
        lhs_after = empty_sso()
    return result, "append", lhs_after, dict(rhs)
