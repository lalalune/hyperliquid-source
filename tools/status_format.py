"""Node #94 status formatter (RE-001, window 0x542f8a0).

Model of the formatter mapped in research/work-items/RE-001-status-format-94:
given a status record (code byte, subcode byte, nullable message string),
produce exactly the string the binary writes into the out string.

Rules pinned from the binary:
- code 0 -> "OK", ignoring subcode and message entirely.
- codes 1..15 -> their fixed prefix, then the suffix rule below.
- any other code byte -> "Unknown code(<code>): ", then the suffix rule.
- suffix rule: subcode 0 appends the message directly when non-null;
  subcode nonzero appends the subcode name, then ": " plus the message
  when the message is non-null. A null message ends the string after the
  prefix (plus the subcode name when subcode is nonzero).
- subcode values above 15 are not pinned by the binary's 16-entry table
  and are rejected here rather than guessed.
"""

CODE_PREFIX = {
    0: "OK",
    1: "NotFound: ",
    2: "Corruption: ",
    3: "Not implemented: ",
    4: "Invalid argument: ",
    5: "IO error: ",
    6: "Merge in progress: ",
    7: "Result incomplete: ",
    8: "Shutdown in progress: ",
    9: "Operation timed out: ",
    10: "Operation aborted: ",
    11: "Resource busy: ",
    12: "Operation expired: ",
    13: "Operation failed. Try again.: ",
    14: "Compaction too large: ",
    15: "Column family dropped: ",
}

SUBCODE_NAME = [
    "",
    "Timeout Acquiring Mutex",
    "Timeout waiting to lock key",
    "Failed to acquire lock due to max_num_locks limit",
    "No space left on device",
    "Deadlock",
    "Stale file handle",
    "Memory limit reached",
    "Space limit reached",
    "No such file or directory",
    "Insufficient capacity for merge operands",
    "Manual compaction paused",
    " (overwritten)",
    "Txn not prepared",
    "IO fenced off",
    "Merge operator failed",
]


def format_status(code, subcode=0, msg=None):
    """Format one status record exactly as window 0x542f8a0 does.

    code: int 0..255 (the status code byte).
    subcode: int 0..15 (the status subcode byte).
    msg: str or None (the message C string; None means a null pointer).
    """
    if not 0 <= code <= 255:
        raise ValueError(f"code byte out of range: {code}")
    if not 0 <= subcode <= 15:
        raise ValueError(f"subcode out of pinned table range: {subcode}")
    if code == 0:
        return "OK"
    if code in CODE_PREFIX:
        out = CODE_PREFIX[code]
    else:
        out = f"Unknown code({code}): "
    if subcode != 0:
        out += SUBCODE_NAME[subcode]
        if msg is not None:
            out += ": " + msg
    elif msg is not None:
        out += msg
    return out
