"""Python model of node #115 OptionTypeInfo::AsCustomSharedPtr<Statistics>.

Pinned by RE-001 work item RE-001-optiontypeinfo-statistics-115
against work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The behaviour: the builder 0x6071520 fills a 0xb8-byte OptionTypeInfo
record for a custom shared_ptr Statistics option (type 22) and
installs the two create hooks at +0x18/+0x20 (the std::function
manager 0x606fa80 and the invoker 0x60780a0, both resolved through
GOT RELATIVE slots). The manager answers the std::function manager
ops; the invoker either takes the "id" fast path (release the
destination shared_ptr and return an empty Status) or forwards to
the create-by-name host 0x6077820, which is pinned by open PR #3386
and is modelled here only through its published contract.

Unknowns kept separate from pinned facts (see the packet README):
the semantic names of the invoker's id-string / name-string args
beyond their observed roles, and the OptionVerificationType /
OptionTypeFlags enum spellings for the raw values 3 / 1 used by the
single installing call site.
"""

TYPE_CUSTOM_SHARED_PTR = 22
RECORD_SIZE = 0xB8

MANAGER = 0x606FA80
INVOKER = 0x60780A0
CREATE_HOST = 0x6077820

# Address of the lambda typeinfo object; its vtable is
# __cxxabiv1::__class_type_info + 0x10 and its name string lives at
# 0x975620 (see the packet relocations.txt).
TYPEINFO_OBJECT = 0x64D2D38
TYPEINFO_NAME = 0x975620

# Packed use/weak-count value meaning use == 1 and weak == 1.
PACKED_LAST = 0x100000001


def build_record(offset, verification, flags):
    """The 0xb8-byte record 0x6071520 writes to out.

    Field map (offsets are bytes from the record start):
      +0x00  offset        (esi)
      +0x08  zero (16 bytes)
      +0x18  manager       0x606fa80 (GOT 0x64eda58)
      +0x20  invoker       0x60780a0 (GOT 0x64eda60)
      +0x28  zero (up to +0xa8)
      +0xa8  type          22 (custom shared_ptr kind)
      +0xac  verification  (edx)
      +0xb0  flags         (ecx)
    The builder first fills an identical stack temporary at rsp+0x10
    and then writes the record field-wise; the only manager call it
    emits (out+0x8, temp+0x8, op 2) is a proven no-op, see
    builder_manager_call().
    """
    record = {"+0x00": offset & 0xFFFFFFFF}
    for off in range(0x08, 0x18, 8):
        record["+%#04x" % off] = 0
    record["+0x18"] = MANAGER
    record["+0x20"] = INVOKER
    for off in range(0x28, 0xA8, 8):
        record["+%#04x" % off] = 0
    record["+0xa8"] = TYPE_CUSTOM_SHARED_PTR
    record["+0xac"] = verification & 0xFFFFFFFF
    record["+0xb0"] = flags & 0xFFFFFFFF
    return record


def builder_manager_call():
    """The manager call inside the builder (site 0x607161e).

    The builder calls the manager with op 2 (clone_functor) on a
    zeroed functor storage. The manager's op-2 branch returns 0
    without touching memory (the lambda captures nothing), so the
    call has no observable effect on the record. Returns the
    manager's return code (0) and the (empty) list of writes.
    """
    return 0, []


def manager(op, functor_ptr=None):
    """The std::function manager 0x606fa80.

    op 0 (get_type_info):  *(out) = 0x64d2d38, the lambda typeinfo.
    op 1 (get_functor_ptr): *(out) = functor_ptr.
    op 2 (clone_functor) / op 3 (destroy_functor) / anything else:
    no-op, returns 0 (the lambda is empty: nothing to copy or free).
    Returns (written_value_or_None, return_code).
    """
    if op == 0:
        return TYPEINFO_OBJECT, 0
    if op == 1:
        return functor_ptr, 0
    return None, 0


class Status:
    """A 16-byte RocksDB Status: code dword at +0x00, subcode word
    at +0x04, state pointer qword at +0x08."""

    def __init__(self, code=0, subcode=0, state=None):
        self.code = code
        self.subcode = subcode
        self.state = state

    @classmethod
    def empty(cls):
        return cls(0, 0, None)

    def is_empty(self):
        return self.code == 0 and self.subcode == 0 and self.state is None

    def __repr__(self):
        return "Status(code=%d, subcode=%d, state=%r)" % (
            self.code, self.subcode, self.state)


class CountedBase:
    """A shared_ptr control block: vtable slots 0x10 (dispose) and
    0x18 (destroy), packed use/weak counts at +0x08."""

    def __init__(self, use=1, weak=1, dispose=None, destroy=None):
        self.use = use
        self.weak = weak
        self.dispose = dispose or (lambda cb: None)
        self.destroy = destroy or (lambda cb: None)
        self.disposed = False
        self.destroyed = False

    def packed(self):
        return (self.weak << 32) | self.use

    def release(self, selector_zero, dispose_fn):
        """The counted release 0x60780a0 inlines (same rule as the
        0x5d35070 helper it calls when the old use-count is 1).

        packed == 0x100000001: zero the counts, call dispose (vtable
        slot 0x10) then destroy (vtable slot 0x18). Otherwise decrement
        the use count (lock xadd when the 0x64ed290 selector byte is
        0, plain decrement otherwise); when the old use-count was 1,
        call dispose_fn (0x5d35070). Returns True when the object was
        disposed, else False.
        """
        if self.packed() == PACKED_LAST:
            self.use = 0
            self.weak = 0
            self.dispose(self)
            self.disposed = True
            self.destroy(self)
            self.destroyed = True
            return True
        old_use = self.use
        # selector_zero only chooses the atomic vs plain decrement;
        # the resulting count is the same either way.
        self.use = old_use - 1
        if old_use == 1:
            dispose_fn(self)
            self.disposed = True
            return True
        return False


class SharedPtr:
    """A 16-byte shared_ptr slot: object pointer + control block."""

    def __init__(self, obj=None, control=None):
        self.obj = obj
        self.control = control

    def is_null(self):
        return self.obj is None and self.control is None


def invoker(out, config_options, id_string, name_string, dest, create_host,
            selector_zero=True, dispose_fn=None):
    """The std::function _M_invoke 0x60780a0.

    out: Status to fill (returned). config_options: passed through
    to the create host as its 2nd arg. id_string (rcx): a string
    whose length must be 2 and whose first two bytes are "id" for the
    fast path. name_string (r8): the factory name handed to the
    create host. dest (r9): pointer to the destination shared_ptr
    slot. create_host: callable modelling 0x6077820 (pinned by open
    PR #3386; see create_host_contract()).

    Fast path (id_string == b"id" and name_string == b""): release
    the shared_ptr at *dest (zero the slot, release its control
    block), write an empty Status to out, return out. Otherwise
    forward to the create host as (out, config_options, name_string,
    *dest) and return out.
    """
    if (len(id_string) == 2 and id_string[:2] == b"id"
            and len(name_string) == 0):
        slot = dest[0]
        if slot is not None and slot.control is not None:
            control = slot.control
            slot.obj = None
            slot.control = None
            control.release(selector_zero,
                            dispose_fn or (lambda cb: None))
        out.code, out.subcode, out.state = 0, 0, None
        return out
    create_host(out, config_options, name_string, dest[0])
    return out


def create_host_contract(out, config_options, name_string, slot):
    """Contract-only model of the create-by-name host 0x6077820.

    The host's internals are pinned by open PR #3386, not here.
    Its published dispatch (from that PR's README): an empty name or
    "BasicStatistics" constructs a fresh StatisticsImpl via ctor
    0x6071a00; a name matching the registrar-built global is released
    with an empty Status; any other name goes through the registry
    lookup 0x609e510 with translator 0x6076b20 and Status builder
    0x61cf670 (open PR #3440). This stub reproduces only the branch
    whose outcome is fixed by that contract and marks the rest as a
    parse-path outcome the caller must resolve. slot is the
    destination shared_ptr slot, installed in place.
    """
    if name_string in (b"", b"BasicStatistics"):
        slot.obj = "StatisticsImpl"
        slot.control = CountedBase()
        out.code, out.subcode, out.state = 0, 0, None
        return "default"
    return "parse_path"
