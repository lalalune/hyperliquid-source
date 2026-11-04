"""Node #115 arena aligned allocation (0x605d7b0) with its slow path (0x605d6c0).

Models, literally as written, the RocksDB-arena-shaped allocator pair found
in the node #115 binary:

* ``allocate_aligned(size, quantum, logger)`` -- window 0x605d7b0:
  when the gate field (+0x8d8) is set, the quantum is nonzero and the size
  is nonzero, the size is rounded up to a multiple of the quantum and a
  fresh block is requested from the grow callee (0x605d000).  A nonzero
  grow result is returned at once with no cursor update.  On a zero grow
  result the failure is reported (level 2, format
  "[%s:119] AllocateAligned fail to allocate huge TLB pages: %s", file
  "memory/arena.cc") and the window falls back to the bump path below.
  Otherwise -- gate clear, quantum zero, or size zero -- the bump path
  runs directly: the cursor (+0x8c8) is aligned up to 16 bytes, the
  aligned pointer is returned, and cursor/remaining (+0x8d0) advance by
  size plus the alignment padding.  If the remaining space cannot cover
  size plus padding, the window tail-jumps to the slow allocator with
  consume flag 1.

* ``slow_allocate(size, consume)`` -- window 0x605d6c0:
  if size exceeds (block hint at +0x810) >> 2, the big-path counter
  (+0x8b8) increments and the block callee (0x605d3c0) is tail-jumped
  with (object, size); its return is the result and no cursor fields
  are installed.  Otherwise the gate field (+0x8d8), when nonzero, is
  passed to the grow callee; a nonzero grow result installs the block,
  a zero grow result reloads the block hint and falls through to the
  block callee with (object, block hint).  Installation sets remaining
  (+0x8d0) to hint minus size; with consume set, cursor (+0x8c8) is
  block start plus size and end (+0x8c0) is block start plus hint;
  with consume clear, cursor is block start and end is block start
  plus remaining.  Both arms return the block start.

Callees 0x605d000 (grow/new block), 0x605d3c0 (block allocation),
0x5fceda0 (report), 0x61d1f30 (error-string construction),
__errno_location, sized operator delete and basic_string::_M_dispose
are by contract: they are injected as hooks, never reimplemented here.
The landing-pad behaviour is modelled too: if the error-string build
or the report raises, a constructed temporary string is disposed and
the exception propagates (the binary stub at 0x605d786 disposes the
string at rsp and resumes unwinding via _Unwind_Resume).
"""

ALIGNMENT = 16
REPORT_FORMAT = "[%s:119] AllocateAligned fail to allocate huge TLB pages: %s"
REPORT_FILE = "memory/arena.cc"
REPORT_LEVEL = 2

# Field offsets within the arena object, as observed in the windows.
OFF_BLOCK_HINT = 0x810
OFF_BIG_COUNTER = 0x8B8
OFF_END = 0x8C0
OFF_CURSOR = 0x8C8
OFF_REMAINING = 0x8D0
OFF_GATE = 0x8D8


class TempString:
    """A temporary error string built from errno.

    ``data`` is the readable text, ``data_ptr`` the buffer address and
    ``aux`` the field at object +0x10.  ``is_sso`` marks the case where
    the data pointer equals the object's own +0x10 buffer, in which
    case the binary frees nothing after the report.
    """

    def __init__(self, data, data_ptr, aux, is_sso=False):
        self.data = data
        self.data_ptr = data_ptr
        self.aux = aux
        self.is_sso = is_sso


class Hooks:
    """Callee hooks.  Tests inject fakes; production use never runs here."""

    def __init__(self, grow=None, new_block=None, report=None,
                 errno=None, build_string=None, dispose=None,
                 sized_delete=None):
        self.grow = grow
        self.new_block = new_block
        self.report = report
        self.errno = errno
        self.build_string = build_string
        self.dispose = dispose
        self.sized_delete = sized_delete


class Arena115:
    """The arena object state plus the two windows' behaviour."""

    def __init__(self, cursor=0, remaining=0, end=0, gate=0,
                 block_hint=0, big_counter=0, hooks=None):
        self.cursor = cursor
        self.remaining = remaining
        self.end = end
        self.gate = gate
        self.block_hint = block_hint
        self.big_counter = big_counter
        self.hooks = hooks if hooks is not None else Hooks()

    def allocate_aligned(self, size, quantum, logger):
        """Window 0x605d7b0: aligned allocation with huge-block first try."""
        if self.gate == 0 or quantum == 0 or size == 0:
            return self._bump(size)
        rounded = ((size - 1) // quantum + 1) * quantum
        block = self.hooks.grow(self, rounded)
        if block != 0:
            return block
        tmp = None
        try:
            tmp = self.hooks.build_string(self.hooks.errno())
            self.hooks.report(REPORT_LEVEL, logger, REPORT_FORMAT,
                              REPORT_FILE, tmp.data)
        except BaseException:
            if tmp is not None:
                self.hooks.dispose(tmp)
            raise
        if not tmp.is_sso:
            self.hooks.sized_delete(tmp.data_ptr, tmp.aux + 1)
        return self._bump(size)

    def _bump(self, size):
        """The 16-byte-aligned bump path shared by both entry routes."""
        ptr = self.cursor
        pad = (-ptr) % ALIGNMENT
        needed = size + pad
        if self.remaining < needed:
            return self.slow_allocate(size, consume=1)
        self.cursor = ptr + needed
        self.remaining -= needed
        return ptr + pad

    def slow_allocate(self, size, consume):
        """Window 0x605d6c0: block install, or the big-path tail jump."""
        if size > (self.block_hint >> 2):
            self.big_counter += 1
            return self.hooks.new_block(self, size)
        if self.gate != 0:
            block = self.hooks.grow(self, self.gate)
            if block != 0:
                return self._install(block, self.gate, size, consume)
        block = self.hooks.new_block(self, self.block_hint)
        return self._install(block, self.block_hint, size, consume)

    def _install(self, block, hint, size, consume):
        self.remaining = hint - size
        if consume:
            self.cursor = block + size
            self.end = block + hint
        else:
            self.cursor = block
            self.end = block + self.remaining
        return block
