"""Model of node #115 routine 0x5f12320: the list range copy
that the copy-on-write move helper uses.

The routine is the range-insert body of a std::list whose nodes
are 0x18 bytes (next at +0x00, prev at +0x08, payload qword at
+0x10); the RE-002 vendor census identifies the FDE
(0x5f12320..0x5f12413, 243 bytes) as a librocksdb-sys
0.11.0+8.1.1 build copy of
``std::list<rocksdb::MemTable*>::insert(const_iterator,
_List_const_iterator, _List_const_iterator)`` (.isra.0). This
model pins the observed behaviour of the window itself.

Arguments (System V): rdi = the destination list object in
full -- its header node is at object +0x00/+0x08 and its size
field is the qword at object +0x10; rsi = the insertion
position node (an iterator into the destination list); rdx =
the first source node; rcx = the source end node (exclusive).
The source range is the forward chain [rdx, rcx) linked by the
+0x00 next pointers. Returns void (rax is caller-owned
garbage).

Observable behaviour, as read from the body:

- Empty range (rdx == rcx): the routine returns at once. It
  writes nothing at all -- not even the destination size.
- Non-empty range: the copies are first built in a private
  on-stack temporary list: for each source node in order, one
  fresh 0x18-byte node is allocated and its payload qword
  (+0x10) is copied from the source node; giving the temp
  header as the hook position links each new node at the temp
  list's tail, so the copies preserve source order and the
  temp list's count is the copied count. A copied node's own
  +0x00/+0x08 link fields hold whatever the _M_hook primitive
  writes; this model receives them from the supplied ``hook``
  function, exactly as the native body receives them from the
  PLT call.
- The finished temp chain is then spliced before the position
  node with a single _M_transfer call: the destination list's
  links change only in that one call.
- The destination object's size field at +0x10 grows by the
  copied count -- and only after the transfer.
- Only then is the temp list drained: each remaining temp node
  is deleted with operator delete(node, 0x18). Because the
  transfer emptied the temp list, this loop normally deletes
  nothing. It is observable only when _M_transfer's
  postcondition (temp list empty) does not hold.
- The source nodes are never written; the destination size is
  never read. The destination's pre-existing nodes are written
  only by the transfer primitive itself.

Exception behaviour (pinned at the landing-pad level): the
FDE's LSDA carries exactly one call-site entry, for the
operator-new call in the copy loop (the body range
0x5f12375..0x5f1237a), landing on the pad at 0x5f12407. The pad
moves the exception object to rbx and jumps directly into the
shared cleanup block at 0x5f122e0, which raw-deletes (size
0x18, no unhook) every node then linked in the temp list and
calls _Unwind_Resume with the original exception object. No
_M_transfer has run at that point, so the destination list is
untouched on this path; the position, header and size
arguments are never reached. The other PLT calls (_M_hook,
_M_transfer, operator delete) have no landing pad: an exception
escaping them terminates.

What the earlier contract got wrong (RE-001-cow-move-helper-
12840-115 cited this routine by contract only, reading its
behaviour off the call sites): the contract's observable claims
are all confirmed -- deep copy, fresh 0x18-byte nodes, payload
qword copied, order preserved, destination size grown by the
copied count, source unmodified. Two mechanism details differ
from a plain reading of the contract: the transfer is one bulk
splice of a fully built temp chain, not a per-node tail
append, and the helper writes the destination *header*
(rdi + 0x00 is the header node) -- the header is not a separate
second argument; the second argument is the insertion position,
which both call sites in the move helper pass as the list's own
base, i.e. its header, so inserts land at the tail.
"""

NODE = 0x18
PAYLOAD_OFFSET = 0x10


class ListCopyInsertError(Exception):
    """Raised on the model's guard failures."""


def _check_span(value, low, high, label):
    if not isinstance(value, int) or isinstance(value, bool) \
            or not low <= value < high:
        raise ListCopyInsertError(
            "%s must be an integer address in [%#x, %#x)"
            % (label, low, high))


class ListCopyInsert:
    """One run of the routine over an abstract memory.

    ``mem`` maps byte addresses to byte values (dict of int to
    int); nodes are 0x18-byte records in it. ``alloc(size)``
    returns the address of a fresh node record; ``free(addr,
    size)`` releases one; ``hook(node, position)`` models the
    _M_hook PLT primitive's writes; ``transfer(position, first,
    last)`` models the _M_transfer PLT primitive's link writes.
    The primitives are supplied by the caller because the
    native body delegates exactly those writes to them; the
    routine's own stores are modelled here directly.
    """

    def __init__(self, mem, alloc, free, hook, transfer):
        self.mem = mem
        self.alloc = alloc
        self.free = free
        self.hook = hook
        self.transfer = transfer
        # Temp-list membership bookkeeping: nodes the hook has
        # linked and the transfer has not moved out. The hook
        # and transfer functions supplied by the caller maintain
        # it through temp_link/temp_unlink; the drain loop after
        # the transfer reads exactly this set.
        self.temp_members = []

    # -- tiny memory helpers over the byte dict ----------------
    def _qword(self, addr):
        value = 0
        for i in range(8):
            value |= self.mem.get(addr + i, 0) << (8 * i)
        return value

    def _store_qword(self, addr, value):
        for i in range(8):
            self.mem[addr + i] = (value >> (8 * i)) & 0xFF

    # -- the routine -------------------------------------------
    def run(self, dest, position, first, last):
        """Run the copy for the range [first, last).

        ``dest`` is the destination list object (header at
        dest + 0x00/+0x08, size qword at dest + 0x10);
        ``position`` is the destination node the copies are
        inserted before; ``first``/``last`` delimit the source
        chain by its +0x00 next pointers. The walk is guarded:
        a chain that never reaches ``last`` raises instead of
        looping forever -- the native body has no such guard,
        so the guard is a model-side safety property only.
        """
        # Entry compare: an empty range returns before any
        # write, including to the destination size.
        if first == last:
            return
        temp = []          # temp list nodes, in link order
        copied = 0
        try:
            cur = first
            while True:
                node = self.alloc(NODE)
                # The body's only own store to the new node:
                # the payload qword, copied from the source.
                self._store_qword(node + PAYLOAD_OFFSET,
                                  self._qword(cur + PAYLOAD_OFFSET))
                self.hook(node, ("temp", 0))
                temp.append(node)
                copied += 1
                cur = self._qword(cur)
                if cur == last:
                    break
        except Exception:
            # Landing pad + shared cleanup: raw-delete every
            # temp-list node (chain order), no unhook, and
            # re-raise. The destination is untouched: no
            # transfer has run and the size add has not run.
            for node in temp:
                self.free(node, NODE)
            raise
        # One bulk splice of the whole temp chain before the
        # position node, then -- and only then -- the size add.
        self.transfer(position, ("temp", 0), ("temp", copied))
        self._store_qword(dest + 0x10,
                          self._qword(dest + 0x10) + copied)
        # Post-transfer drain: delete every node still linked in
        # the temp list. A contract-faithful transfer leaves
        # none; the loop is live code whenever it does not.
        for node in list(self.temp_members):
            self.free(node, NODE)

    # -- temp-list bookkeeping for the supplied primitives ----
    def temp_link(self, node):
        """Called by the supplied hook model when it links a
        fresh node into the temp list."""
        self.temp_members.append(node)

    def temp_unlink(self, node):
        """Called by the supplied transfer model when it moves
        a node out of the temp list."""
        self.temp_members.remove(node)


def list_copy_insert(mem, alloc, free, hook, transfer,
                     dest, position, first, last):
    """Functional wrapper: run the routine once and return the
    machine object (for inspection of the bookkeeping)."""
    machine = ListCopyInsert(mem, alloc, free, hook, transfer)
    machine.run(dest, position, first, last)
    return machine
