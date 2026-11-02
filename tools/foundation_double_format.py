"""Model of node #94 function 0x514c050: format one double with "%f".

Evidence: research/work-items/RE-001-double-format-94/ (RE-001).
The function writes the "%f" rendering of its double vararg into the
output string object: SSO storage when the rendering is at most 15
bytes, heap storage (exact-fit capacity) otherwise. A negative
vsnprintf return is not modelled (see the packet README).
"""

SSO_THRESHOLD = 15
BUFFER_SIZE = 0x148
FORMAT = "%f"


def format_double(value):
    """Return the "%f" rendering of value, as the target's format does."""
    return "%f" % value


def build_string(value):
    """Model the output string object for one double value.

    Returns a dict with the rendered text, the storage arm, and the
    object fields the target writes: pointer description, length, and
    the union slot (+0x10) contents.
    """
    text = format_double(value)
    length = len(text)
    if length <= SSO_THRESHOLD:
        return {
            "text": text,
            "storage": "sso",
            "pointer": "own+0x10",
            "length": length,
            "union_slot": "sso buffer bytes",
            "terminator_at": "buffer+length",
        }
    return {
        "text": text,
        "storage": "heap",
        "pointer": "_M_create block",
        "length": length,
        "union_slot": length,
        "terminator_at": "pointer+length",
    }
