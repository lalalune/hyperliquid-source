"""Python model of node #115 routine 0x5d50030 (RE-001 counter refresh).

The routine takes a state pointer in rdi and refreshes the counter slot
reached through state + 0x18, then optionally runs a waiter dispatch
(phase B). The producer (vtable slot 0x98) and the handler (vtable slot
0xc8) are virtual targets whose implementations are not pinned here,
so they enter the model as values: slot98 (compared against the known
producer 0x5d4d490), producer_value (the result of whichever producer
call runs), slot_c8 (compared against the known handler 0x5d48960) and
waiter_byte (the byte at waiter + 0x20).

State fields: counter (None for a null counter pointer, else the stored
qword), flag20 (accumulate 0 / replace nonzero), flag21 (run phase B),
flag22 (extra subtract), sub38, sub28. All arithmetic is 64-bit
wrapping. refresh returns (counter, exit, ops): counter is the stored
value after the run (None when the counter pointer is null), exit is
"return", "handler_call" or "tail_dispatch", and ops records the
observable steps in order.
"""

MASK = (1 << 64) - 1
KNOWN_PRODUCER = 0x5D4D490
KNOWN_HANDLER = 0x5D48960


def _phase_b(counter, ops, slot_c8, waiter_byte):
    """Run phase B; return (counter, exit, ops)."""
    if slot_c8 != KNOWN_HANDLER:
        ops.append(("handler", "direct_call"))
        return counter, "handler_call", ops
    if waiter_byte <= 2:
        return counter, "return", ops
    ops.append(("handler", "tail_dispatch"))
    return counter, "tail_dispatch", ops


def refresh(counter, flag20, flag21, flag22, sub38, sub28, producer_value,
            slot98=KNOWN_PRODUCER, slot_c8=KNOWN_HANDLER, waiter_byte=0):
    """Run the 0x5d50030 behaviour; return (counter, exit, ops)."""
    ops = []
    if counter is None:
        # Null-counter path: phase A skipped; slot 0x98 still called
        # when flag21 is set, but its adjusted result is unconsumed.
        if flag21 == 0:
            return None, "return", ops
        ops.append(("producer_null_path",
                    (producer_value - sub38) & MASK, "computed_unconsumed"))
        return _phase_b(None, ops, slot_c8, waiter_byte)
    # Phase A.
    if slot98 == KNOWN_PRODUCER:
        ops.append(("producer", "delegate"))
    else:
        ops.append(("producer", "direct"))
    if flag20 == 0:
        counter = (counter + producer_value - sub38) & MASK
    else:
        counter = (producer_value - sub38) & MASK
    if flag22 != 0:
        counter = (counter - sub28) & MASK
    ops.append(("store", counter))
    if flag21 == 0:
        return counter, "return", ops
    return _phase_b(counter, ops, slot_c8, waiter_byte)
