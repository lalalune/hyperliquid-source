# RE-004 — Selected node #115 borrow/lend query error messages

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Scope is the normal message-building path for two selected query reply variants. Existing [user](../RE-004-bole-user-reply-115/) and [reserve](../RE-004-bole-reserve-reply-115/) packets identify the callers and builder slot. The [generic display packet](../action-wire-error-display-115/) establishes the outer tag and callback argument.

The user query site at `0x38e61a1` supplies raw tag `0xf1` and subtype `0x00`. The reserve query site at `0x38e694f` supplies `0xf1` and `0x0c`. Both call relocated slot `0x64e9570`. The wrapper at `0x3d4eb60` passes a temporary output slot and zero in EDX to `0x46de430`, copies the three output words to the caller's slot, then calls `0x3d57b80` with the original tag pointer.

The builder's `0xf1` arm initializes a three-word value to `[0, 1, 0]` and passes its address through a formatter descriptor. After the formatter returns zero in AL, the builder copies the resulting three words to its output. The master formatter passes the byte at tag offset 2 to the nested callback at `0x41c68e0` under the known prefix `Borrow/Lend error: `.

The callback handles subtype 12 directly with 14 bytes of `Internal error`. Subtype 0 goes through relocated slot `0x64ea670` and the first entry of a signed-relative dispatch table. That arm passes 13 bytes of `Invalid token` to the same formatter method at vtable offset `0x18`. Thus the two selected error descriptions on successful formatting are `Borrow/Lend error: Invalid token` and `Borrow/Lend error: Internal error`. Error conditions before either call, formatter failure, the sink's internals and other subtypes remain outside this packet.

Reproduce from the repository root with `PYTHONPATH=tools python3 research/work-items/RE-004-node115-bole-query-error-text/verify.py`. The verifier reads the pinned ELF and checks disassembly bytes, relative targets, relocations, table entries and literals. It does not execute target instructions.
