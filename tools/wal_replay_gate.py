"""Python model of node #94's WAL replay gate, window 0x4fa87a0.

Faithful to research/work-items/RE-001-wal-replay-gate-94/records.json:
an optional virtual pre-call, a write-prepared flag gate (decision 3),
an unsigned written-sequence gate (decision 1), and otherwise a
delegation to the WAL replay caller 0x520e830 with forwarded arguments.

The model deliberately does not execute the replay caller: it returns
the exact call arguments the binary would pass, so tests can pin the
forwarding contract. Sequence values are unsigned 64-bit quantities,
matching the binary's jae comparison.
"""

FLAG_MESSAGE = ("This API is not yet compatible with "
                "write-prepared/write-unprepared transactions")
SEQUENCE_MESSAGE = "Requested sequence not yet written in the db"
MASK64 = (1 << 64) - 1


class Status:
    """The 16-byte out status: decision byte plus owning message."""

    def __init__(self, decision=0, message=None):
        self.decision = decision & 0xFF
        self.message = message

    def __repr__(self):  # pragma: no cover - debugging aid
        return f"Status(decision={self.decision}, message={self.message!r})"


def build_detail(status, decision, message):
    """Detail builder 0x542f040 on the paths this window uses.

    The second string argument has length 0 here, so the stored
    buffer is exactly the message. A previous message is freed
    first, which the model expresses as replacement.
    """
    status.decision = decision & 0xFF
    status.message = message
    return status


def replay_gate(out, ctx_flag_970, ctx_obj_610_present, written_limit,
                requested, b, c, d_value, pre_call_log=None):
    """Run the gate. Returns ("report", out) or ("replay", call_args).

    ctx_flag_970: byte at context +0x970 (nonzero reports decision 3).
    ctx_obj_610_present: whether the context +0x610 pointer is non-null.
    written_limit: qword at (context +0x68 field) +0x108.
    requested: this window's rdx argument.
    b, c: this window's rcx and r8 arguments, forwarded unchanged.
    d_value: value of the context +0x68 field, forwarded as r9.
    pre_call_log: optional list receiving the virtual pre-call record.
    """
    if ctx_obj_610_present:
        if pre_call_log is not None:
            pre_call_log.append(("vtable_slot_0xb0", 0x3C, 1))
    if ctx_flag_970:
        build_detail(out, 3, FLAG_MESSAGE)
        return ("report", out)
    if (requested & MASK64) > (written_limit & MASK64):
        build_detail(out, 1, SEQUENCE_MESSAGE)
        return ("report", out)
    call_args = {
        "out": out,
        "ctx": "context+0x1518",
        "a": requested,
        "b": b,
        "c": c,
        "d": d_value,
    }
    return ("replay", call_args)
