"""Model of node #115 routine 0x5f12840: the copy-on-write
prepare's move helper.

The routine (FDE 0x5f12840..0x5f129a6, 358 bytes) is the callee
the merged drain-driver packet (RE-001-drain-driver-115) left by
contract only: in the copy-on-write prepare at 0x5f13f90 it is
called as move(new, outer + 0x18, inner) -- rdi is the freshly
allocated 0x50-byte object, rsi is a pointer stored verbatim,
rdx is the old (source) object -- and the packet recorded that
"the field-by-field contents moved by 0x5f12840 ... are unknown"
and that "the 0x5f12840/0x5f12320 list-move area was judged too
tangled to pin honestly in earlier cycles". This model pins the
routine's own instructions field by field.

Object layout (0x50 bytes), as written by the routine itself:

    +0x00  list-1 header _M_next      +0x08  list-1 header _M_prev
    +0x10  list-1 node count (qword)
    +0x18  list-2 header _M_next      +0x20  list-2 header _M_prev
    +0x28  list-2 node count (qword)
    +0x30  dword copied from the source object's +0x30
    +0x34  NEVER WRITTEN by this routine (see below)
    +0x38  qword copied from the source object's +0x38
    +0x40  dword reference count, set to 0 (the prepare's init
           callee at 0x5f12a00 then increments it; pinned by
           RE-001-refcount-increment-12a00-115)
    +0x48  the rsi argument, stored verbatim

List nodes are 0x18 bytes: +0x00 _M_next, +0x08 _M_prev,
+0x10 payload pointer. The payload's dword at payload +0x70 is
the per-payload reference count this routine increments.

What the routine does, in its own instruction order:

  1. Prologue field writes: both list headers are self-linked
     (empty), both counts are zeroed, the +0x30 dword and the
     +0x38 qword are copied from the source, the +0x40 count is
     zeroed, and rsi is stored at +0x48. The dword at +0x34 is
     not written on any path: whatever the allocator left there
     stays there.
  2. If the source is the destination itself (rdx == rdi), the
     routine returns at once after step 1. (The only file-wide
     caller passes a fresh allocation, so this is a guard the
     binary carries, not a case the caller can reach.)
  3. List 1: if the source list 1 is nonempty, the routine
     calls the list-copy helper 0x5f12320 (by contract, below)
     to deep-copy the source list 1 into the destination list 1,
     then walks the destination list 1 and increments the
     +0x70 dword of every node's payload by one (plain addl:
     wraps modulo 2**32, no lock prefix).
  4. List 2 carries a full reconciliation block as written:
       a. The routine walks the source list 2 and the
          destination list 2 in lockstep, overwriting each
          destination node's payload slot (+0x10) with the
          source node's payload.
       b. If the source runs out first, the destination's
          surplus nodes from the cursor on are destroyed one
          by one: the +0x28 count is decremented (subq, 64-bit)
          per node, the node is unlinked with
          std::list's _List_node_base::_M_unhook, and freed
          with operator delete(node, 0x18).
       c. If the destination runs out first, the routine calls
          the list-copy helper on the remaining source range,
          deep-copying the rest of the source list 2 onto the
          tail of the destination list 2.
       d. Finally the routine walks the whole destination
          list 2 and increments every node's payload +0x70
          dword by one, exactly as in step 3.
     Reachability, stated plainly: step 1 self-linked the
     destination list-2 header and the step-3 helper writes
     only list 1 of the destination, so the destination
     list-2 cursor read at the top of this step is always the
     header itself -- on the step-3 path because the reload
     at 0x5f128bd returns the just-written header, and on the
     skipped-step-3 path because the cursor starts at the
     header outright. The lockstep walk (a) therefore never
     executes its body and the destroy loop (b) never
     destroys a node: any nodes a caller might have linked
     into the destination list 2 beforehand are orphaned by
     step 1, neither overwritten, bumped, unlinked nor freed.
     What runs on every call is (c) over the whole source
     list 2, then (d). The model below keeps the as-written
     structure; the prologue writes make it take the same
     paths the binary takes.
  5. The routine returns void. Callee-saved registers are
     restored; the exception landing pad at 0x5f1299a (which
     jumps to the shared cleanup block at 0x5f127f6: raw
     operator delete of every node then in list 2, then of
     every node then in list 1, then _Unwind_Resume) is the
     only other way control leaves the body, and is not
     modelled here -- the model covers runs in which allocation
     succeeds, as in the packet's differential.

The list-copy helper 0x5f12320 is BY CONTRACT ONLY in this
packet: its body is not claimed. Its contract, read from its
call sites and its observable effect, is what list_copy_range
below implements: deep-copy the source node range
[src_first, src_header) -- for each source node, in order,
allocate a fresh 0x18-byte node, copy the source node's +0x10
payload qword into it, and append it to the destination list
whose header is dest_header; then add the number of copied
nodes to the qword at dest_base + 0x10. The source list is not
modified. At the two call sites in this routine dest_base ==
dest_header (the object base for list 1, object + 0x18 for
list 2), so the count that grows is that list's own count
field.

Memory interface: `mem` is a bytearray addressed by absolute
address minus MEM_BASE (MEM_BASE = 0 in the model's own
coordinate system; callers translate). `alloc` is an object
with alloc(size) -> address and free(address, size); the model
records frees through it but never reuses a freed address,
exactly as the differential harness's bump allocator behaves.
"""

NODE_SIZE = 0x18
PAYLOAD_COUNTER_OFFSET = 0x70

LIST1_HEADER = 0x00
LIST1_COUNT = 0x10
LIST2_HEADER = 0x18
LIST2_COUNT = 0x28
SCALAR_DWORD = 0x30
SCALAR_QWORD = 0x38
REFCOUNT = 0x40
STORED_POINTER = 0x48
OBJECT_SIZE = 0x50


def _rd64(mem, addr):
    return int.from_bytes(mem[addr:addr + 8], "little")


def _wr64(mem, addr, value):
    mem[addr:addr + 8] = (value & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def _rd32(mem, addr):
    return int.from_bytes(mem[addr:addr + 4], "little")


def _wr32(mem, addr, value):
    mem[addr:addr + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


def _bump_payload(mem, payload):
    _wr32(mem, payload + PAYLOAD_COUNTER_OFFSET,
          (_rd32(mem, payload + PAYLOAD_COUNTER_OFFSET) + 1) & 0xFFFFFFFF)


def list_unhook(mem, node):
    """The _List_node_base::_M_unhook contract: splice the node
    out of its circular list by joining its neighbours. The
    node's own +0x00/+0x08 fields are left as they were."""
    nxt = _rd64(mem, node)
    prv = _rd64(mem, node + 8)
    _wr64(mem, prv, nxt)
    _wr64(mem, nxt + 8, prv)


def list_copy_range(mem, dest_base, dest_header, src_first, src_header,
                    alloc):
    """Model of the by-contract list-copy helper 0x5f12320:
    deep-copy the source range [src_first, src_header) onto the
    tail of the destination list headed at dest_header, and add
    the copied count to the qword at dest_base + 0x10."""
    fresh_nodes = []
    node = src_first
    while node != src_header:
        fresh = alloc.alloc(NODE_SIZE)
        _wr64(mem, fresh + 0x10, _rd64(mem, node + 0x10))
        fresh_nodes.append(fresh)
        node = _rd64(mem, node)
    if not fresh_nodes:
        return
    for i in range(len(fresh_nodes) - 1):
        _wr64(mem, fresh_nodes[i], fresh_nodes[i + 1])
        _wr64(mem, fresh_nodes[i + 1] + 8, fresh_nodes[i])
    tail = _rd64(mem, dest_header + 8)
    _wr64(mem, fresh_nodes[0] + 8, tail)
    _wr64(mem, tail, fresh_nodes[0])
    _wr64(mem, fresh_nodes[-1], dest_header)
    _wr64(mem, dest_header + 8, fresh_nodes[-1])
    _wr64(mem, dest_base + 0x10,
          _rd64(mem, dest_base + 0x10) + len(fresh_nodes))


def _bump_list(mem, header):
    node = _rd64(mem, header)
    while node != header:
        payload = _rd64(mem, node + 0x10)
        node = _rd64(mem, node)
        _bump_payload(mem, payload)


def cow_move_helper(mem, this, refs, old, alloc):
    """Run the move helper 0x5f12840 against the model memory.

    `this` is the destination object (rdi), `refs` the stored
    pointer argument (rsi), `old` the source object (rdx).
    Effects are written into `mem`; allocations and frees go
    through `alloc`. Only non-throwing runs are modelled.
    """
    # Step 1: prologue field writes, in instruction order.
    _wr64(mem, this + 0x00, this)
    _wr64(mem, this + 0x08, this)
    _wr64(mem, this + LIST1_COUNT, 0)
    _wr32(mem, this + SCALAR_DWORD, _rd32(mem, old + SCALAR_DWORD))
    _wr64(mem, this + LIST2_COUNT, 0)
    _wr64(mem, this + SCALAR_QWORD, _rd64(mem, old + SCALAR_QWORD))
    _wr32(mem, this + REFCOUNT, 0)
    _wr64(mem, this + STORED_POINTER, refs)
    header2 = this + LIST2_HEADER
    _wr64(mem, this + LIST2_HEADER, header2)
    _wr64(mem, this + LIST2_HEADER + 8, header2)

    # Step 2: self-copy guard.
    if old == this:
        return

    # Step 3: list 1. The destination cursor for step 4 starts
    # at the destination list-2 first node when this step ran,
    # and at the list-2 header itself when it was skipped.
    if _rd64(mem, old + LIST1_HEADER) != old:
        list_copy_range(mem, this, this, _rd64(mem, old + LIST1_HEADER),
                        old, alloc)
        _bump_list(mem, this + LIST1_HEADER)
        cursor_this = _rd64(mem, this + LIST2_HEADER)
    else:
        cursor_this = header2

    # Step 4: list 2 reconciliation.
    src_header = old + LIST2_HEADER
    src_node = _rd64(mem, old + LIST2_HEADER)
    dst_node = cursor_this
    if src_node != src_header and cursor_this != header2:
        # Lockstep payload overwrite (step 4a).
        while True:
            payload = _rd64(mem, src_node + 0x10)
            src_node = _rd64(mem, src_node)
            _wr64(mem, dst_node + 0x10, payload)
            dst_node = _rd64(mem, dst_node)
            if dst_node == header2:
                break
            if src_node == src_header:
                break
    if src_node == src_header:
        # Step 4b: destroy the destination's surplus tail.
        node = dst_node
        while node != header2:
            nxt = _rd64(mem, node)
            _wr64(mem, this + LIST2_COUNT,
                  (_rd64(mem, this + LIST2_COUNT) - 1)
                  & 0xFFFFFFFFFFFFFFFF)
            list_unhook(mem, node)
            alloc.free(node, NODE_SIZE)
            node = nxt
    else:
        # Step 4c: deep-copy the remaining source range.
        list_copy_range(mem, header2, header2, src_node, src_header,
                        alloc)
    # Step 4d: bump every payload now in the destination list 2.
    _bump_list(mem, this + LIST2_HEADER)
