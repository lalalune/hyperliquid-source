"""Python model of node #115 OptionTypeInfo::AsCustomSharedPtr<SystemClock>.

Pinned by RE-001 work item RE-001-optiontypeinfo-systemclock-115
against work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The behaviour: the builder 0x5fd0180 fills a 0xb8-byte OptionTypeInfo
record for a custom shared_ptr SystemClock option (type 22) and
installs it into out through the record-copy helper 0x5e332c0. The
two create hooks live at +0x18/+0x20: the std::function manager
0x5fcc660 and the invoker 0x5fd4c30, both resolved through GOT
RELATIVE slots. The manager answers the std::function manager ops;
the invoker either takes the "id" fast path (release the destination
shared_ptr and return an empty Status) or forwards to the
create-by-name host 0x5fd46c0, which resolves the name against the
current clock (function-local static accessor 0x5fe2680, a
PosixClock) and otherwise creates the default clock through the
registry translator (by contract, open PR #3440) and the
name-to-clock factory helper 0x5fd4080 (by contract). The host's
name dispatch compares vtable slots 0x80/0x90 against the
default implementations 0x5d2e770 (the name predicate: input
equals the slot-0x70 or slot-0x90 name) and 0x5d2ca10 (returns
the empty string); both were read in full.

The sibling Statistics builder 0x6071520 (open PR #3685) writes the
same record field map but installs it field-wise instead of through
the copy helper; the SliceTransform sibling builder 0x6083a90 shares
this builder's copy-helper install shape and is a separate work item.

Unknowns kept separate from pinned facts (see the packet README):
the semantic names of the invoker's id-string / name-string args
beyond their observed roles, the OptionVerificationType /
OptionTypeFlags enum spellings for the raw values 1 / 0x2000 used
by the single installing call site, and the translator / factory /
registry contracts cited by contract only.
"""

TYPE_CUSTOM_SHARED_PTR = 22
RECORD_SIZE = 0xB8

BUILDER = 0x5FD0180
MANAGER = 0x5FCC660
INVOKER = 0x5FD4C30
CREATE_HOST = 0x5FD46C0
ACCESSOR = 0x5FE2680
DEFAULT_INIT = 0x5FD20D0
STATUS_MOVE = 0x5FCDF70
COPY_HELPER = 0x5E332C0
FACTORY_HELPER = 0x5FD4080

# Address of the lambda typeinfo object; its vtable is
# __cxxabiv1::__class_type_info + 0x10 and its name string lives at
# 0x972460 (see the packet relocations.txt).
TYPEINFO_OBJECT = 0x64CDA00
TYPEINFO_NAME = 0x972460

# Packed use/weak-count value meaning use == 1 and weak == 1.
PACKED_LAST = 0x100000001

# The default clock's tables (see the packet relocations.txt).
POSIX_CLOCK_TABLE = 0x64CE930
POSIX_CLOCK_CONTROL_TABLE = 0x64CED00

# The host's name-dispatch sentinels (RELATIVE-resolved globals).
SENTINEL_SLOT_0X80 = 0x5D2E770
SENTINEL_SLOT_0X90 = 0x5D2CA10

# The atomicity selector byte for the counted use-count bump.
ATOMICITY_SELECTOR = 0x64ED290


def build_record(offset, verification, flags):
    """The 0xb8-byte record 0x5fd0180 writes (as a stack temporary).

    Field map (offsets are bytes from the record start):
      +0x00  offset        (esi)
      +0x04  padding       (NEVER written by the builder or the copy
                           helper; its content is indeterminate)
      +0x08  zero (16 bytes)
      +0x18  manager       0x5fcc660 (GOT 0x64ed8d0)
      +0x20  invoker       0x5fd4c30 (GOT 0x64ed958)
      +0x28  zero (up to +0xa8)
      +0xa8  type          22 (custom shared_ptr kind)
      +0xac  verification  (edx)
      +0xb0  flags         (ecx)
    The builder first fills this stack temporary at rsp+0x20 and
    then installs it into out with the record-copy helper 0x5e332c0
    (site 0x5fd0266). The only manager call the builder emits after
    the copy (out+0x8, temp+0x8, op 3) is a proven no-op, see
    builder_temp_cleanup().
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


def builder_temp_cleanup():
    """The cleanup the builder runs after the copy (sites 0x5fd0280
    and 0x5fd0285).

    The manager call with op 3 (destroy_functor) on the temporary's
    functor storage returns 0 without touching memory (the lambda
    captures nothing), and the record destructor 0x5d3f950 is a
    no-op here because the functor members at +0x58/+0x78/+0x98 are
    all zero. Returns the manager's return code (0) and the (empty)
    list of writes.
    """
    return 0, []


def manager(op, functor_ptr=None):
    """The std::function manager 0x5fcc660.

    op 0 (get_type_info):  *(out) = 0x64cda00, the lambda typeinfo.
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


def copy_record(out, src):
    """The record-copy helper 0x5e332c0 (OptionTypeInfo
    copy-assignment).

    out and src are dicts in the build_record() shape, extended with
    the five std::function members at +0x08/+0x28/+0x48/+0x68/+0x88.
    Each member is a dict {"functor": ..., "manager": addr-or-None,
    "invoker": addr-or-None}. The helper copies the offset, then for
    each member: zeroes the destination member, clones it through
    the source member's manager with op 2 when the manager is
    non-null, and copies the manager+invoker pair. It then copies
    type+verification (8 bytes at +0xa8) and flags (4 bytes at
    +0xb0). The +0x04 padding dword is never written. Returns out.
    """
    out["+0x00"] = src["+0x00"]
    members = ("+0x08", "+0x28", "+0x48", "+0x68", "+0x88")
    for m in members:
        out[m] = {"functor": None, "manager": None, "invoker": None}
        src_member = src.get(m)
        if src_member is not None and src_member.get("manager") is not None:
            manager(2)
            out[m] = dict(src_member)
    out["+0xa8"] = src["+0xa8"]
    out["+0xac"] = src["+0xac"]
    out["+0xb0"] = src["+0xb0"]
    return out


class Status:
    """A 16-byte RocksDB Status: code byte at +0x00, subcode and
    severity bytes at +0x01..+0x05, state pointer qword at +0x08."""

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


def status_move(dst, src):
    """The Status move-assignment 0x5fcdf70 (dst = std::move(src)).

    dst == src returns dst at once. Otherwise: copy bytes 0..5 from
    src to dst; zero src bytes 1..5 (src byte 0, the code, is left
    intact); move the state pointer from src to dst, freeing dst's
    old state when non-null; src state becomes null. Returns dst.
    """
    if dst is src:
        return dst
    dst.code, dst.subcode = src.code, src.subcode
    old_state = dst.state
    dst.state = src.state
    src.subcode = 0
    src.state = None
    if old_state is not None:
        del old_state
    return dst


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
        """The counted release _M_release 0x5d350c0 (pinned by open
        PR #3674).

        packed == 0x100000001: zero the counts, call dispose (vtable
        slot 0x10) then destroy (vtable slot 0x18). Otherwise
        decrement the use count (lock xadd when the 0x64ed290
        selector byte is 0, plain decrement otherwise); when the old
        use-count was 1, call dispose_fn (0x5d35070). Returns True
        when the object was disposed, else False.
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


class Clock:
    """A SystemClock object as the create host sees it.

    name_70: the name vtable slot 0x70 returns (or None).
    name_90: the name vtable slot 0x90 returns (or None).
    predicate_80: what vtable slot 0x80 returns for a name, or
        None when the slot equals the default implementation
        (SENTINEL_SLOT_0X80) and is skipped.
    slot_90_is_default: True when vtable slot 0x90 equals the
        default implementation (SENTINEL_SLOT_0X90).
    """

    def __init__(self, name_70=None, name_90=None, predicate_80=None,
                 slot_90_is_default=False):
        self.name_70 = name_70
        self.name_90 = name_90
        self.predicate_80 = predicate_80
        self.slot_90_is_default = slot_90_is_default


class ClockAccessor:
    """The function-local-static accessor 0x5fe2680.

    guard: the __cxa_guard byte at 0x6504c98. static_control: the
    static at 0x6504ca0 (the control-block pointer, None before
    initialization). The slow path allocates the 0x10-byte control
    block and the 0x30-byte combined allocation whose PosixClock
    object sits at +0x10 (table 0x64ce930, packed counts
    0x100000001 copied from the global at 0x459b20). current()
    returns the control block.
    """

    def __init__(self):
        self.guard = False
        self.static_control = None
        self._static_slot = None

    def current(self):
        if self.guard:
            return self.static_control, self._static_slot
        control = CountedBase(use=1, weak=1)
        clock = Clock(name_70=b"SystemClock", name_90=None,
                      predicate_80=None, slot_90_is_default=True)
        slot = SharedPtr(obj=clock, control=control)
        self.static_control = control
        self._static_slot = slot
        self.guard = True
        return control, slot


def default_init(registry):
    """The pthread_once initializer 0x5fd20d0.

    Builds the "TimeEmulatedSystemClock" name string, allocates the
    0x30-byte registry entry and the 0x70-byte clock object (table
    0x64d8ec0+0x10, byte +0x48 = 1), and inserts the entry into the
    mutex-guarded registry under the name "SystemClock". The registry
    structure and the 0x5fcd890 / 0x61f8b60 / 0x5fcd6f0 / 0x5fd1da0 /
    0x61f8700 contracts are open; only the allocation sizes, the
    table pointer, the two name literals and the lock/insert/unlock
    shape are pinned. Returns the name under which the clock was
    registered.
    """
    _built_name = b"TimeEmulatedSystemClock"
    clock = Clock(name_70=b"SystemClock", name_90=None,
                  predicate_80=None, slot_90_is_default=True)
    registry[b"SystemClock"] = clock
    return b"SystemClock"


def default_slot_0x80_predicate(clock, name_string):
    """The default slot-0x80 name predicate 0x5d2e770 (FDE
    0x5d2e770..0x5d2e832), read in full.

    Returns False for an empty input name; otherwise True when the
    input equals the clock's slot-0x70 name (strlen + memcmp) or,
    failing that, its slot-0x90 name (null -> False; strlen +
    memcmp); otherwise False. The create host inlines exactly this
    logic when the clock's slot 0x80 is this default.
    """
    if len(name_string) == 0:
        return False
    if clock.name_70 is not None and name_string == clock.name_70:
        return True
    if clock.name_90 is not None and name_string == clock.name_90:
        return True
    return False


def default_slot_0x90_name():
    """The default slot-0x90 name getter 0x5d2ca10 (FDE
    0x5d2ca10..0x5d2ca1c): 7 bytes, lea of the empty string at
    0x4376fd and ret. The default second name is empty."""
    return b""


def invoker(out, config_options, id_string, name_string, dest, create_host,
            selector_zero=True, dispose_fn=None):
    """The std::function _M_invoke 0x5fd4c30.

    out: Status to fill (returned). config_options: passed through
    to the create host as its 2nd arg. id_string (rcx): a string
    whose length must be 2 and whose first two bytes are "id" for the
    fast path. name_string (r8): the factory name handed to the
    create host. dest (r9): pointer to the destination shared_ptr
    slot. create_host: callable modelling 0x5fd46c0 (pinned below).

    Fast path (id_string == b"id" and name_string == b""): release
    the shared_ptr at *dest (zero the slot, release its control
    block via _M_release 0x5d350c0 — unlike the Statistics invoker,
    this invoker does not inline the packed fast path; it lives
    inside _M_release, pinned by open PR #3674), write an empty
    Status to out, return out. Otherwise forward to the create host
    as (out, config_options, name_string, *dest) and return out.
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


def create_host(out, config_options, name_string, slot, current_slot,
                translator, factory, second_translator,
                error_status_builder=None, selector_zero=True):
    """The create-by-name host 0x5fd46c0.

    out: Status to fill (returned). config_options: a dict with key
    "byte_1" (the byte at config_options+1 whose meaning is open).
    name_string: the name to resolve. slot: the destination
    shared_ptr slot. current_slot: the current clock's SharedPtr
    (from the accessor 0x5fe2680; the host bumps its use count on
    load). translator: callable (config_options, name_string) ->
    (Status, translated_name, error) modelling the registry
    translator 0x609e510 (by contract, open PR #3440). factory:
    callable (config_field, translated_name, slot) -> Status
    modelling the name-to-clock factory helper 0x5fd4080 (by
    contract). second_translator: callable (Status, config_options,
    dest_obj, current_obj) -> Status modelling 0x609e2d0 (by
    contract). error_status_builder: callable (code, message, name)
    -> Status modelling 0x61cf670 (by contract).

    Dispatch: slot-0x80 predicate (when it differs from the default
    implementation) decides first; an empty name goes to the default
    path; slot-0x70's name matching adopts; slot-0x90's name (when
    it differs from the default implementation) matching adopts;
    otherwise the default path. Adopt installs the current clock
    into slot (releasing the old control when it differs) and writes
    an empty Status. The default path runs pthread_once (0x5fd20d0)
    and the translator, then: translator Status code != 0 -> out =
    move(translator Status); code == 0 and translated name non-empty
    -> factory + Status normalization; code == 0, name empty, error
    non-null -> error Status code 3 "Cannot reset object " + name;
    code == 0, name empty, error null -> release slot, empty Status.
    """
    current = current_slot.obj
    control = current_slot.control
    if control is not None:
        control.use += 1
    # Slot-0x80 predicate (skipped when it is the default).
    if current.predicate_80 is not None:
        if not current.predicate_80(name_string):
            return _default_path(out, config_options, name_string, slot,
                                 current_slot, translator, factory,
                                 second_translator, error_status_builder,
                                 selector_zero)
    if len(name_string) == 0:
        return _default_path(out, config_options, name_string, slot,
                             current_slot, translator, factory,
                             second_translator, error_status_builder,
                             selector_zero)
    if current.name_70 is not None and name_string == current.name_70:
        return _adopt(out, slot, current_slot, selector_zero)
    if not current.slot_90_is_default:
        if current.name_90 is not None and name_string == current.name_90:
            return _adopt(out, slot, current_slot, selector_zero)
    return _default_path(out, config_options, name_string, slot,
                         current_slot, translator, factory,
                         second_translator, error_status_builder,
                         selector_zero)


def _adopt(out, slot, current_slot, selector_zero):
    old_control = slot.control
    slot.obj = current_slot.obj
    slot.control = current_slot.control
    if (old_control is not None and old_control is not current_slot.control):
        if current_slot.control is not None:
            current_slot.control.use += 1
        old_control.release(selector_zero, lambda cb: None)
    out.code, out.subcode, out.state = 0, 0, None
    return out


def _default_path(out, config_options, name_string, slot, current_slot,
                  translator, factory, second_translator,
                  error_status_builder, selector_zero):
    trans_status, translated_name, error = translator(
        config_options, name_string)
    if trans_status.code != 0:
        return status_move(out, trans_status)
    if len(translated_name) != 0:
        factory_status = factory(config_options.get("field_0x40"),
                                 translated_name, slot)
        intermediate = Status()
        status_move(intermediate, factory_status)
        if intermediate.code == 3 and config_options.get("byte_1"):
            out.code, out.subcode, out.state = 0, 0, None
            return out
        if intermediate.code == 0:
            second = second_translator(intermediate, config_options,
                                       slot.obj, current_slot.obj)
            status_move(intermediate, second)
        return status_move(out, intermediate)
    if error is not None:
        if error_status_builder is not None:
            err = error_status_builder(3, b"Cannot reset object ", error)
        else:
            err = Status(code=3, state=b"Cannot reset object " + error)
        return status_move(out, err)
    if slot.control is not None:
        control = slot.control
        slot.obj = None
        slot.control = None
        control.release(selector_zero, lambda cb: None)
    out.code, out.subcode, out.state = 0, 0, None
    return out
