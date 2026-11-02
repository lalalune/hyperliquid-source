"""Python model of node #115 value resolve-and-store (0x5f09e90).

RE-001 work item. The model follows the window's observed behavior,
not a C++ spelling: the exact source name of the function and of
its arguments is inference, the mechanics below are the window's.

Observed arguments
------------------
host (rdi): an object whose +0x6c field (32-bit) is the store width.
value_ptr (rsi): when non-null, the resolved value is the qword
    loaded from it; when null, the hash-fold path runs instead.
first_slice (rdx): a 16-byte record, +0x00 pointer and +0x08 length,
    hashed first with seed 0 (hash path only).
second_slice (rcx): a 16-byte record, +0x00 pointer and +0x08 length,
    hashed second with seed 0xd28aad72f49bd50b (hash path only).
byte_input (r8b): one byte, hashed third with seed
    0xa5155ae5e937aa16 (hash path only).
qword_input (r9): one qword, hashed fourth as eight little-endian
    bytes with seed 0x77a00858ddd37f21 (hash path only).
out (7th argument): the slot the resolved value is stored into.

Behavior (one function, end to end)
-----------------------------------
1. Width = host+0x6c (32-bit). Width 0 returns at once: no load,
   no hash call, no store.
2. Direct path (value_ptr non-null): value = the qword at
   value_ptr; no hash call runs.
3. Hash path (value_ptr null): value = h1 ^ h2 ^ h3 ^ h4, where
   h1 = H(first_slice bytes, 0),
   h2 = H(second_slice bytes, 0xd28aad72f49bd50b),
   h3 = H(bytes([byte_input]), 0xa5155ae5e937aa16),
   h4 = H(qword_input as 8 little-endian bytes,
           0x77a00858ddd37f21).
   The hash callee 0x61c3530's body is cited by contract in the
   packet, so the model takes the hash as an injected function:
   tests pin the fold structure, call order and truncation, not
   the hash itself.
4. Store: width 1 stores the low byte, width 2 the low word,
   width 4 the low dword, width 8 the full qword, all at out+0x00
   (bytes beyond the stored width are untouched). Widths 3, 5, 6,
   7 and above 8 store nothing. The function documents no return
   value; its observable effect is the store (or its absence).
"""

MASK64 = (1 << 64) - 1

SEED_FIRST = 0x0000000000000000
SEED_SECOND = 0xD28AAD72F49BD50B
SEED_BYTE = 0xA5155AE5E937AA16
SEED_QWORD = 0x77A00858DDD37F21

WIDTH_BYTES = {1: 1, 2: 2, 4: 4, 8: 8}


def resolve_and_store(host_width, out, value=None, first=b"",
                      second=b"", byte_input=0, qword_input=0,
                      hash_fn=None, calls=None):
    """Resolve the value and store it truncated by host_width.

    out is a mutable bytearray of at least 8 bytes; only the stored
    width's bytes at offset 0 are written. value is the qword that
    would be loaded from value_ptr, or None for the hash path.
    first/second are the slice byte strings. hash_fn(data, seed)
    must return the hash callee's 64-bit result; calls, when given,
    records (data, seed) for every hash call in order. Returns
    (stored, value): stored is True when bytes were written, value
    is the resolved qword, or None when width 0 returns early.
    """
    width = host_width & 0xFFFFFFFF
    if width == 0:
        return False, None
    if value is not None:
        resolved = value & MASK64
    else:
        if hash_fn is None:
            raise ValueError("hash path needs hash_fn")
        def call(data, seed):
            if calls is not None:
                calls.append((data, seed))
            return hash_fn(data, seed) & MASK64
        resolved = (
            call(first, SEED_FIRST)
            ^ call(second, SEED_SECOND)
            ^ call(bytes([byte_input & 0xFF]), SEED_BYTE)
            ^ call((qword_input & MASK64).to_bytes(8, "little"),
                   SEED_QWORD)
        )
    nbytes = WIDTH_BYTES.get(width)
    if nbytes is None:
        return False, resolved
    out[0:nbytes] = (resolved & MASK64).to_bytes(8, "little")[:nbytes]
    return True, resolved
