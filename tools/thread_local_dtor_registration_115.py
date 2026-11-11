"""Python model of node #115's thread-local destructor registration.

RE-001 work item; see
research/work-items/RE-001-thread-local-dtor-registration-115/ for the
evidence packet. The model reproduces the binary behaviour exactly as the
excerpts show it; nothing here is an implementation claim about the
upstream reconstruction.

Layout (TLS slots, relative to %fs:0x0)
----------------------------------------
  -0x1150 guard      0 = active, -1 = registering, 1 = drained
  -0x1148 capacity   fallback vector capacity
  -0x1140 vec_ptr    entry array pointer (8 = Vec::new() dangling pointer)
  -0x1138 count      entry count; entries are 16-byte (t, dtor) pairs
  -0x428  guard_struct_ptr  guard object + 0x10
  -0x420  guard_epoch

register_dtor 0x5ca0d20 (t, dtor):
  fast path — GOT 0x64ec9b0 (__cxa_thread_atexit_impl) non-null: tail-jump
  to it with (dtor, t, 0x64fe448) where 0x64fe448 is the GOT slot holding
  __dso_handle (0x64efa20) itself.
  slow path — guard must be 0 (else panic at 0x5ca0de6); guard = -1;
  key::enable 0x5ca0e20; grow when count == capacity (new capacity =
  max(4, 2 * old), helper 0x5c8b980); append (t, dtor); guard = 0.

key::enable 0x5ca0e20: creates the pthread key once (BSS key var
0x64feda8; destructor function from GOT 0x64fedb0 -> runner 0x5ca53f0),
CAS-installs it (the race loser deletes its spare key), then
pthread_setspecific(key, 1) on every call.

dtor_runner 0x5ca53f0 (pthread-key destructor callback): panics if the
guard is non-zero at entry; drains the vector LIFO (count -= 1; call
vec[count].dtor(vec[count].t)); frees the array and resets
(capacity, vec_ptr, count) to (0, 8, 0); guard += 1; then handles the
guard object at %fs:-0x428 (guard dtor via GOT 0x64dfe58 -> 0x5c98b40
when its refcount hits 0).

Guard object (0x30 bytes, malloc'd by guard_alloc 0x5c9d1f0):
+0x00 refcount = 1, +0x08 = 1, +0x10 epoch from the global counter at
0x6500050, +0x18 = 0, +0x28 = 0. guard_use bumps the refcount and
re-stores guard+0x10 at %fs:-0x428; guard_free clears the first byte of
the string at guard+0x18, invokes the callback at guard+0x20 if
non-null, then lock decq guard+0x08.

Census (callers.tsv): 1153 sites in 604 caller FDEs, 28 distinct
destructors. Two dominant TLS objects: -0x1130 (845 sites, arc-dec
dtors, state byte +0x48) and -0x1180 (287 sites, slice-drop dtors,
state byte +0x20).
"""

# TLS slot offsets relative to %fs:0x0.
GUARD_SLOT = -0x1150
CAPACITY_SLOT = -0x1148
VEC_PTR_SLOT = -0x1140
COUNT_SLOT = -0x1138
GUARD_STRUCT_PTR_SLOT = -0x428
GUARD_EPOCH_SLOT = -0x420

DSO_HANDLE_SLOT = 0x64FE448
DSO_HANDLE = 0x64EFA20
GOT_CXA_THREAD_ATEXIT = 0x64E0510
GOT_CXA_THREAD_ATEXIT_IMPL = 0x64EC9B0
GOT_GROW_ONE = 0x64EC878
GOT_KEY_DTOR_FN = 0x64FEDB0
KEY_VAR = 0x64FEDA8
DANGLING_PTR = 8  # Vec::new() dangling pointer for 8-aligned entries
GLOBAL_EPOCH_COUNTER = 0x6500050

REGISTER_DTOR = 0x5CA0D20
KEY_ENABLE = 0x5CA0E20
DTOR_RUNNER = 0x5CA53F0
GUARD_ALLOC = 0x5C9D1F0
GUARD_USE = 0x5CA44A0
GUARD_FREE = 0x5C98B40
GROW_ONE = 0x5C8B620
GROW_HELPER = 0x5C8B980

# Census, pinned by research/work-items/RE-001-thread-local-dtor-registration-115/.
CENSUS_SITES = 1153
CENSUS_CALLER_FDES = 604
CENSUS_DTORS = 28
# dtor address -> (shape, state-byte offset, sites)
DTOR_TABLE = {
    0x15B6CA0: ("slice-drop", 0x20, 3),
    0x15B6CC0: ("arc-dec", 0x48, 32),
    0x1619FE0: ("arc-dec-call", 0x08, 1),
    0x16293A0: ("multi-slice-drop", 0xA0, 1),
    0x16F0F10: ("arc-dec", 0x48, 16),
    0x26A0570: ("inner-counter-callback", 0x08, 1),
    0x26A05D0: ("slice-drop", 0x20, 173),
    0x26A05F0: ("arc-dec", 0x48, 76),
    0x2E941A0: ("arc-dec", 0x48, 1),
    0x3F11060: ("inner-counter-callback", 0x08, 1),
    0x3F110C0: ("arc-dec", 0x48, 1),
    0x4752F70: ("oncecell-state", 0x18, 1),
    0x4752FE0: ("delegate-call", 0x38, 1),
    0x4780330: ("slice-drop", 0x20, 2),
    0x4E390E0: ("inner-counter-callback", 0x08, 1),
    0x4E39140: ("arc-dec", 0x48, 68),
    0x4E39190: ("slice-drop", 0x20, 109),
    0x5BB5200: ("global-refcount-dec", 0x28, 1),
    0x5BB9630: ("non-atomic-dec-tail", 0x08, 1),
    0x5BC1830: ("inner-counter-callback", 0x08, 1),
    0x5C7F7D0: ("arc-dec-tail", 0x08, 2),
    0x5C7F7F0: ("call-then-arc-dec", 0x08, 2),
    0x5CCC7E0: ("inner-counter-callback", 0x08, 1),
    0x5CD8510: ("arc-dec-tail", 0x08, 1),
    0x5CDF3E0: ("arc-dec-call", 0x08, 1),
    0x5CDF410: ("arc-dec", 0x48, 651),
    0x5CFFCA0: ("arc-dec-at-0x10", 0x28, 2),
    0x5D00840: ("arc-dec-at-0x10", 0x28, 2),
}
# TLS offset -> (sites, destructor family)
TLS_OBJECTS = {
    -0x1130: (845, "arc-dec"),
    -0x1180: (287, "slice-drop"),
    -0x10E0: (4, "arc-dec-at-0x10"),
    -0x470: (2, "call-then-arc-dec"),
    -0x480: (2, "arc-dec-tail"),
    "caller-passed": (13, "mixed"),
}


class RegistrationPanic(Exception):
    """Raised when register_dtor is called while the guard is non-zero
    (re-entrant registration, or registration after the dtors drained)."""


class RunnerPanic(Exception):
    """Raised when the dtor runner is entered while the guard is non-zero."""


def grow_capacity(old_cap):
    """New capacity from the grow helper 0x5c8b980: max(4, 2 * old)."""
    return max(4, 2 * old_cap)


class KeyState:
    """Models key::enable 0x5ca0e20: the pthread key at BSS 0x64feda8."""

    def __init__(self):
        self.key = 0  # BSS key var, initial 0
        self.setspecific_calls = 0
        self.spare_keys_deleted = 0

    def enable(self):
        """Create the key once (CAS-install); setspecific(key, 1) every time.
        Returns True when this call created the key."""
        created = False
        if self.key == 0:
            self.key = 1  # pthread_key_create; any non-zero key value
            created = True
        self.setspecific_calls += 1
        return created

    def race_loser(self):
        """The losing side of the creation race deletes its spare key."""
        self.spare_keys_deleted += 1


class DtorRegistry:
    """The per-thread fallback registry: the TLS slots at -0x1150..-0x1138
    plus the pthread key that carries the runner."""

    def __init__(self):
        self.guard = 0
        self.capacity = 0
        self.vec_ptr = DANGLING_PTR
        self.entries = []  # list of (t, dtor)
        self.key = KeyState()
        self.freed = False

    @property
    def count(self):
        return len(self.entries)

    def register_dtor(self, t, dtor, impl_present=False):
        """register_dtor 0x5ca0d20. With the libc impl present, dispatches
        to it and returns the (dtor, t, dso_handle) it would be called
        with; otherwise runs the pthread-key fallback."""
        if impl_present:
            return ("fast-path", dtor, t, DSO_HANDLE_SLOT)
        if self.guard != 0:
            raise RegistrationPanic(f"guard is {self.guard}, registration refused")
        self.guard = -1
        self.key.enable()
        if self.count == self.capacity:
            self.capacity = grow_capacity(self.capacity)
            self.freed = False
        self.entries.append((t, dtor))
        self.guard = 0
        return ("slow-path", dtor, t, DSO_HANDLE_SLOT)

    def run_dtors(self):
        """dtor_runner 0x5ca53f0: drain LIFO, free the array, reset the
        slots. Returns the list of (dtor, t) calls in the order made."""
        if self.guard != 0:
            raise RunnerPanic(f"guard is {self.guard} at runner entry")
        calls = []
        while self.entries:
            t, dtor = self.entries.pop()
            calls.append((dtor, t))
            dtor(t)
        self.freed = True
        self.capacity = 0
        self.vec_ptr = DANGLING_PTR
        self.guard += 1
        return calls


class GuardObject:
    """The 0x30-byte guard object (guard_alloc / guard_use / guard_free)."""

    SIZE = 0x30

    def __init__(self, epoch):
        self.refcount = 1  # +0x00
        self.second = 1  # +0x08
        self.epoch = epoch  # +0x10, from the global counter 0x6500050
        self.string_first_byte = 0  # +0x18
        self.callback = None  # +0x20
        self.extra = 0  # +0x28
        self.callback_calls = []

    @classmethod
    def alloc(cls, epoch_counter):
        """guard_alloc 0x5c9d1f0: malloc(0x30), epoch from the global
        counter, key::enable, guard+0x10 stored at %fs:-0x428."""
        epoch_counter[0] += 1
        return cls(epoch_counter[0])

    def use(self):
        """guard_use 0x5ca44a0: lock incq (*guard)."""
        self.refcount += 1

    def free(self):
        """guard_free 0x5c98b40: clear the string's first byte, invoke the
        callback at +0x20 if non-null, lock decq guard+0x08."""
        self.string_first_byte = 0
        if self.callback is not None:
            self.callback_calls.append(self.callback)
            self.callback()
        self.second -= 1


class TlsObject:
    """A thread-local object as a destructor sees it: a byte-addressable
    struct with a state byte, a discriminant qword and a refcounted inner
    object. Field offsets are the ones the destructor bodies use."""

    def __init__(self, state_offset, discriminant=0, refcount=1):
        self.state_offset = state_offset
        self.state = 0  # the state byte, 0 = live, 1 = registered, 2 = dropped
        self.discriminant = discriminant  # the qword at +0x08
        self.refcount = refcount  # the Arc-like count the dtor decrements
        self.dropped_via = None
        self.dropped = False

    def mark_dropped(self):
        self.state = 2

    def arc_dec_drop(self, drop_a, drop_b):
        """The +0x48 arc-dec shape (0x5cdf410 family): mark +0x48 = 2,
        then by the discriminant at +0x08 (2 = already dropped, return;
        0 -> drop_a, 1 -> drop_b) decrement the refcount at +0x10 and
        call the drop helper when it hits 0."""
        self.mark_dropped()
        if self.discriminant == 2:
            return None
        self.refcount -= 1
        if self.refcount == 0:
            self.dropped = True
            self.dropped_via = drop_a if self.discriminant == 0 else drop_b
            return self.dropped_via
        return None

    def slice_drop(self, count, elem_size=0x38):
        """The +0x20 slice-drop shape: mark +0x20 = 2, drop count
        elements of elem_size bytes starting at +0x10."""
        self.mark_dropped()
        self.dropped = True
        self.dropped_via = ("slice", count, elem_size)
        return self.dropped_via

    def inner_counter_callback(self, inner_counter, callback):
        """The +0x08 inner-counter shape: old state must be 1, else
        panic; decrement the inner counter at +0x820 and invoke the
        callback at +0x818 when it hits 0."""
        if self.state != 1:
            raise RegistrationPanic(f"inner-counter dtor with state {self.state}, want 1")
        self.mark_dropped()
        inner_counter[0] -= 1
        if inner_counter[0] == 0 and callback is not None:
            callback()
            return True
        return False


def census_summary():
    """The 1153-site census as pinned in callers.tsv / records.json."""
    return {
        "sites": CENSUS_SITES,
        "distinct_caller_fdes": CENSUS_CALLER_FDES,
        "distinct_dtors": CENSUS_DTORS,
        "tls_objects": TLS_OBJECTS,
        "dtor_site_counts": {hex(a): v[2] for a, v in DTOR_TABLE.items()},
    }
