"""Model of node #115 routine 0x5a52490: the shared release routine
for one embedded cell.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes one argument in rdi: a pointer to a cell with
this layout (offsets from the cell base):

  +0x00  dword state. The value 2 is the released/empty state:
         the routine returns at once and touches nothing else.
         The low byte of the same dword later selects which of
         the two shared destructors runs when the refcount dies.
  +0x08  pointer to a refcount qword (lock-dec target).
  +0x10..+0x2f  not read or written by this routine directly.
  +0x30  callback table pointer, or 0.
  +0x38  callback data value, passed in rdi to the callback.

End to end, in order, for a cell whose state dword is not 2:

1. First callee: an indirect call through slot 0x64dfe40
   (RELATIVE addend 0x5ceafd0) with rdi = the cell itself. Its
   return value is discarded; nothing the routine does next
   depends on it. Its body is not modelled.
2. Pair release on the +0x08 field: rax = [+0x08];
   lock dec qword [rax]. Only when the decrement reaches 0, one
   destructor is called with rdi = cell + 8, chosen by the byte
   at +0x00: nonzero -> slot 0x64dfdc8 (addend 0x5ce8da0);
   zero -> slot 0x64dfdb8 (addend 0x5ce86d0). The destructor
   bodies are not modelled.
3. Callback: rax = [+0x30]. If rax is 0 the routine returns.
   Otherwise it restores its saved registers and tail-jumps to
   [rax + 0x18] with rdi = [+0x38], so the callback returns
   directly to this routine's caller.

Unwind behaviour is pinned by the routine's LSDA call-site
table (decoded in the packet's verify.py):

  - If step 1 raises, the landing pad at 0x5a524ef first runs
    the pair release again through the standalone helper
    0x5a4f0e0 (43 bytes; the same decrement-and-select on the
    +0x08 field, ending in a tail jump to the chosen
    destructor), then performs step 3 as a call, then calls
    _Unwind_Resume (PLT 0x63f0a50).
  - If a step-2 destructor raises, the landing pad at
    0x5a524ea performs only step 3 as a call and then
    _Unwind_Resume; the pair release is not run a second time.
  - If any call inside those cleanup pads raises, the LSDA
    sends control to 0x5a52512 (action 1), which calls through
    slot 0x64df4c0 into the 20-byte shim at 0x1680cab: it loads
    the 36-byte message "panic in a destructor during cleanup"
    (at 0x46e9bd, length 0x24) and calls through slot 0x64e1f28
    (addend 0x1680e40). The final indirect call at 0x5a52512
    is also the byte sequence that follows the _Unwind_Resume
    call in the FDE; _Unwind_Resume does not return.

NOT modelled: what the cell, the refcounted allocation, the two
destructors, the first callee, or the callback denote at a
higher level; who writes the state dword or the +0x30/+0x38
pair; and the bodies of every callee. The [+0x30] / call-through
[table + 0x18] shape matches the drop slot of a raw-waker
vtable, but this packet pins only the offsets, the null test,
and the argument; it does not claim the callback is a waker.
A null +0x08 pointer on a non-released cell raises in the
model: the binary would fault on the lock dec of address 0,
so the model refuses instead of inventing a release.
"""

ROUTINE = 0x5A52490
ROUTINE_FDE = (0x5A52490, 0x5A52518)
ROUTINE_SIZE = 0x88

STATE_OFFSET = 0x00
REFCOUNT_POINTER_OFFSET = 0x08
CALLBACK_TABLE_OFFSET = 0x30
CALLBACK_DATA_OFFSET = 0x38
RELEASED_STATE = 2

FIRST_CALLEE_SLOT = 0x64DFE40
FIRST_CALLEE = 0x5CEAFD0
FIRST_CALLEE_FDE = (0x5CEAFD0, 0x5CEB1A4)

DESTRUCTOR_NONZERO_SLOT = 0x64DFDC8
DESTRUCTOR_NONZERO = 0x5CE8DA0
DESTRUCTOR_NONZERO_FDE = (0x5CE8DA0, 0x5CE90C1)
DESTRUCTOR_ZERO_SLOT = 0x64DFDB8
DESTRUCTOR_ZERO = 0x5CE86D0
DESTRUCTOR_ZERO_FDE = (0x5CE86D0, 0x5CE8855)

PAIR_HELPER = 0x5A4F0E0
PAIR_HELPER_FDE = (0x5A4F0E0, 0x5A4F10B)

CALLBACK_ENTRY_OFFSET = 0x18

UNWIND_RESUME = 0x63F0A50

PANIC_SHIM_SLOT = 0x64DF4C0
PANIC_SHIM = 0x1680CAB
PANIC_SHIM_FDE = (0x1680CAB, 0x1680CBF)
PANIC_MESSAGE_ADDRESS = 0x46E9BD
PANIC_MESSAGE = "panic in a destructor during cleanup"
PANIC_MESSAGE_LENGTH = 0x24
PANIC_ENTRY_SLOT = 0x64E1F28
PANIC_ENTRY = 0x1680E40

PAD_FOR_FIRST_CALLEE = 0x5A524EF
PAD_FOR_DESTRUCTOR = 0x5A524EA
PAD_FOR_CLEANUP = 0x5A52512


class CleanupPanic(Exception):
    """A second exception escaped a cleanup pad: the binary calls
    the 0x1680cab shim ('panic in a destructor during cleanup')
    instead of resuming the unwind."""


class Cell:
    """The released cell, reduced to the fields the routine reads.

    state: the dword at +0x00 (its low byte is the destructor
    selector). refcount: the integer behind the +0x08 pointer, or
    None to model a null +0x08 pointer. callback_table: the
    +0x30 value (0 = absent). callback_data: the +0x38 value.
    """

    def __init__(self, state, refcount, callback_table=0,
                 callback_data=0):
        self.state = state
        self.refcount = refcount
        self.callback_table = callback_table
        self.callback_data = callback_data

    @property
    def selector_byte(self):
        return self.state & 0xFF


def _pair_release(cell, events, fails):
    """Decrement the +0x08 refcount; on reaching 0 call the
    selector-chosen destructor with the +0x08 field address.
    Shared verbatim by the main path, the standalone helper
    0x5a4f0e0, and both cleanup pads."""
    if cell.refcount is None:
        raise ValueError("null +0x08 refcount pointer")
    cell.refcount -= 1
    events.append(("dec", cell.refcount))
    if cell.refcount == 0:
        if cell.selector_byte != 0:
            destructor = DESTRUCTOR_NONZERO
        else:
            destructor = DESTRUCTOR_ZERO
        events.append(("destructor", destructor, "cell+0x8"))
        if "destructor" in fails:
            raise RuntimeError("destructor raised")


def _callback(cell, events, fails, tail):
    """The +0x30/+0x38 step: absent table means no call at all.
    On the main path it is a tail jump; in cleanup pads a call."""
    if cell.callback_table == 0:
        return False
    events.append(("callback-tail" if tail else "callback-call",
                   cell.callback_table + CALLBACK_ENTRY_OFFSET,
                   cell.callback_data))
    if "callback" in fails:
        raise RuntimeError("callback raised")
    return True


def release(cell, events, fail=None):
    """Run the routine on `cell`, appending observable events.

    `fail` injects raises at named steps: "first" (the
    0x5ceafd0 call), "destructor", "callback" -- one name or a
    set of names. Returns "noop" (state
    was already 2), "returned" (no callback table), or
    "tail-called" (the callback was tail-jumped to). A raise
    from a main-path step propagates after its cleanup pad has
    run; a raise inside a cleanup pad raises CleanupPanic.
    """
    if isinstance(fail, str):
        fails = {fail}
    else:
        fails = set(fail or [])
    if cell.state == RELEASED_STATE:
        events.append(("noop",))
        return "noop"
    try:
        events.append(("first-callee", FIRST_CALLEE, "cell"))
        if "first" in fails:
            raise RuntimeError("first callee raised")
    except RuntimeError:
        # Landing pad 0x5a524ef: pair release via the standalone
        # helper, the callback step as a call, then resume.
        try:
            events.append(("pair-helper", PAIR_HELPER))
            _pair_release(cell, events, fails)
            _callback(cell, events, fails, tail=False)
        except RuntimeError:
            events.append(("cleanup-panic", PANIC_SHIM,
                           PANIC_MESSAGE))
            raise CleanupPanic(PANIC_MESSAGE)
        events.append(("resume", UNWIND_RESUME))
        raise
    try:
        _pair_release(cell, events, fails)
    except RuntimeError:
        # Landing pad 0x5a524ea: callback step as a call, then
        # resume. The pair release is NOT run a second time.
        try:
            _callback(cell, events, fails, tail=False)
        except RuntimeError:
            events.append(("cleanup-panic", PANIC_SHIM,
                           PANIC_MESSAGE))
            raise CleanupPanic(PANIC_MESSAGE)
        events.append(("resume", UNWIND_RESUME))
        raise
    if _callback(cell, events, fails, tail=True):
        return "tail-called"
    return "returned"
