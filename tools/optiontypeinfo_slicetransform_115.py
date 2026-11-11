"""Model of the node #115 OptionTypeInfo::AsCustomSharedPtr<SliceTransform>
builder (0x6083a90) and its create hooks (manager 0x607d190, invoker
0x60809e0, create host 0x61ca3d0, registry find 0x61c9d70, once
initializer 0x61ccfa0).

Pinned against work/hl-node-115.bin (SHA-256
a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).
The record layout, the copy helper, the Status move and the
counted-release shape are shared with the SystemClock sibling
(open PR #3715); the create host's dispatch is this builder's own:
translator -> registry find -> entry factory -> shared_ptr install,
with the three code-4 error arms.
"""

MANAGER = 0x607D190
INVOKER = 0x60809E0
TYPEINFO = 0x64D3018
TYPEINFO_NAME = 0x976100
COPY_HELPER = 0x5E332C0
RECORD_DTOR = 0x5D3F950
RELEASE = 0x5D350C0
DISPOSE_HELPER = 0x5D35070
TRANSLATOR = 0x609E510
SECOND_TRANSLATOR = 0x609E2D0
STATUS_BUILDER = 0x61CF670
REGISTRY_FIND = 0x61C9D70
DEFAULT_INIT = 0x61CCFA0
CONTROL_TABLE = 0x64D7888
CONTROL_TYPEINFO = 0x64D75C0
CONTROL_TYPEINFO_NAME = 0x97E600
PACKED_COUNTS = 0x100000001
ONCE_CONTROL = 0x6508928
ATOMICITY_SELECTOR = 0x64ED290
HASH_SEED = 0xC70F6907
HASH_THRESHOLD = 0x14
TYPE_NAME = b"SliceTransform"


def build_record(offset, verification, flags):
    """The 0xb8-byte record the builder 0x6083a90 writes.

    The +0x04 padding dword is never written by the builder or by
    the copy helper, so it is absent from the model.
    """
    return {
        "+0x00": offset,
        "+0x08": 0,
        "+0x10": 0,
        "+0x18": MANAGER,
        "+0x20": INVOKER,
        "+0x28": 0,
        "+0x30": 0,
        "+0x38": 0,
        "+0x40": 0,
        "+0x48": 0,
        "+0x50": 0,
        "+0x58": 0,
        "+0x60": 0,
        "+0x68": 0,
        "+0x70": 0,
        "+0x78": 0,
        "+0x80": 0,
        "+0x88": 0,
        "+0x90": 0,
        "+0x98": 0,
        "+0xa0": 0,
        "+0xa8": 22,
        "+0xac": verification,
        "+0xb0": flags,
    }


def builder_temp_cleanup():
    """The builder's normal-path cleanup (sites 0x6083b90..0x6083c19).

    Six manager-op-3 destroys: the stack functor, then each of the
    temporary record's five std::function members in turn. Every one
    is a proven no-op: the lambda captures nothing (its manager's op
    3 returns 0 without touching memory) and the other four members
    are zero. The record destructor 0x5d3f950 runs only on the
    landing pad. Returns (code, writes): the builder writes nothing
    after the copy.
    """
    return 0, []


def manager(op, functor_ptr=None):
    """The std::function manager 0x607d190.

    Op 0 returns the typeinfo object 0x64d3018; op 1 copies the
    functor pointer; ops 2 (clone), 3 (destroy) and anything else
    return 0 without touching memory.
    """
    if op == 0:
        return TYPEINFO, 0
    if op == 1:
        return functor_ptr, 0
    return None, 0


def copy_record(out, src):
    """The record-copy helper 0x5e332c0, as pinned by open PR #3715.

    Copies the 4-byte offset, then for each of the five
    std::function members (+0x08/+0x28/+0x48/+0x68/+0x88) zeroes
    the destination member, clones it through the source member's
    manager with op 2 when the manager is non-null, and copies the
    manager+invoker pair; then copies type+verification (8 bytes at
    +0xa8) and flags (4 bytes at +0xb0). The +0x04 padding is never
    written.
    """
    out["+0x00"] = src["+0x00"]
    for member in ("+0x08", "+0x28", "+0x48", "+0x68", "+0x88"):
        src_member = src.get(member, 0)
        if isinstance(src_member, dict) and src_member.get("manager") is not None:
            manager(2)
            out[member] = {"functor": src_member.get("functor"),
                           "manager": src_member["manager"],
                           "invoker": src_member["invoker"]}
        else:
            out[member] = {"functor": None, "manager": None, "invoker": None}
    for field in ("+0x10", "+0x30", "+0x38", "+0x40", "+0x50", "+0x58",
                  "+0x60", "+0x70", "+0x78", "+0x80", "+0x90", "+0x98",
                  "+0xa0"):
        out[field] = src.get(field, 0)
    out["+0xa8"] = src["+0xa8"]
    out["+0xac"] = src["+0xac"]
    out["+0xb0"] = src["+0xb0"]
    return out


class Status:
    """A RocksDB Status: (code, subcode, state-string-or-None)."""

    def __init__(self, code=0, subcode=0, state=None):
        self.code = code
        self.subcode = subcode
        self.state = state

    def is_empty(self):
        return self.code == 0 and self.subcode == 0 and self.state is None

    def __repr__(self):
        return "Status(%d, %d, %r)" % (self.code, self.subcode, self.state)


def status_move(dst, src):
    """The Status move-assignment 0x5fcdf70, as pinned by #3715.

    Copies code and subcode, moves the state string, and zeroes the
    source's subcode and state (its code byte is left alone).
    A self-move is a no-op.
    """
    if dst is src:
        return dst
    dst.code = src.code
    dst.subcode = src.subcode
    dst.state = src.state
    src.subcode = 0
    src.state = None
    return dst


def status_from_message(code, msg1, msg2):
    """The two-slice Status builder 0x61cf670 (by contract).

    Builds a Status with the given code, subcode 0, and a message
    made of the two slices joined by the builder's separator. The
    exact separator is the builder's business and is not pinned
    here; the model joins with a single space.
    """
    if msg1 and msg2:
        state = msg1 + b" " + msg2
    elif msg1:
        state = msg1
    else:
        state = msg2
    return Status(code=code, subcode=0, state=state)


class CountedBase:
    """A _Sp_counted_base control block: use/weak counts plus the
    dispose/destroy hooks the _M_release helper 0x5d350c0 calls."""

    def __init__(self, use=1, weak=1, dispose=None, destroy=None,
                 table=CONTROL_TABLE):
        self.use = use
        self.weak = weak
        self.table = table
        self.dispose = dispose
        self.destroy = destroy
        self.disposed = False
        self.destroyed = False

    def packed(self):
        return (self.use & 0xFFFFFFFF) | ((self.weak & 0xFFFFFFFF) << 32)

    def release(self, selector_zero, dispose_helper):
        """_M_release 0x5d350c0, as pinned by open PR #3674.

        packed == 0x100000001: zero the counts, call dispose
        (vtable slot 0x10) then destroy (vtable slot 0x18).
        Otherwise decrement the use count (lock xadd when the
        0x64ed290 selector byte is 0, plain decrement otherwise);
        when the old use-count was 1, call the dispose helper
        (0x5d35070). Returns True when the object was disposed,
        else False.
        """
        if self.packed() == PACKED_COUNTS:
            self.use = 0
            self.weak = 0
            self._dispose()
            self._destroy()
            return True
        old_use = self.use
        # selector_zero only chooses the atomic vs plain decrement;
        # the resulting count is the same either way.
        self.use = old_use - 1
        if old_use == 1:
            dispose_helper(self)
            self.disposed = True
            return True
        return False

    def _dispose(self):
        self.disposed = True
        if self.dispose is not None:
            self.dispose(self)

    def _destroy(self):
        self.destroyed = True
        if self.destroy is not None:
            self.destroy(self)


class SharedPtr:
    """A 16-byte shared_ptr slot: (object, control block)."""

    def __init__(self, obj=None, control=None):
        self.obj = obj
        self.control = control

    def release(self):
        """Release this slot the way the invoker's "id" path and the
        host's empty-name path do: zero the slot, then _M_release
        the old control block when non-null."""
        control = self.control
        self.obj = None
        self.control = None
        if control is not None:
            control.release(True, lambda c: c._dispose())


def invoker(out, config_options, id_string, name_string, dest, host):
    """The std::function _M_invoke 0x60809e0.

    If the id string is exactly b"id" and the name is empty, release
    the destination shared_ptr and return an empty Status without
    calling the host. Otherwise forward to the create host with
    (out, config_options, name_string, *dest_slot) and return out.
    The functor argument is discarded: the lambda is empty.
    """
    if len(id_string) == 2 and id_string[:2] == b"id" and len(name_string) == 0:
        dest[0].release()
        out.code, out.subcode, out.state = 0, 0, None
        return out
    host(out, config_options, name_string, dest[0])
    return out


class Registry:
    """The registry the find 0x61c9d70 walks.

    buckets: a list of type nodes, in registry order (the binary
    walks them backwards). Each type node is (type_name, entries)
    where entries is a list of (predicate, functor) pairs.
    parent: the fallback registry, or None.
    """

    def __init__(self, buckets=None, parent=None):
        self.buckets = list(buckets or [])
        self.parent = parent


def find_registry(registry, key):
    """The registry find 0x61c9d70.

    Returns the create functor of the first entry whose predicate
    matches the key inside the "SliceTransform" type node, or None
    when nothing matches (the out std::function stays zeroed). If
    the local registry is exhausted, the find recurses into the
    parent registry. The binary switches to a hash lookup when a
    bucket holds more than HASH_THRESHOLD (0x14) entries; the
    observable result (first predicate match in the matched type
    node) is the same, so the model uses one scan.
    """
    for type_name, entries in reversed(registry.buckets):
        if type_name != TYPE_NAME:
            continue
        for predicate, functor in entries:
            if predicate(key):
                return functor
        return None
    if registry.parent is not None:
        return find_registry(registry.parent, key)
    return None


def create_host(out, config_options, name, dest, translator, registry,
                second_translator, error_status_builder=status_from_message):
    """The create-by-name host 0x61ca3d0.

    translator(cfg, name, dest_obj) -> (status, translated_name):
        the registry translator 0x609e510 (by contract).
    registry: the Registry the find 0x61c9d70 walks.
    second_translator(intermediate, cfg, obj, cur) -> Status:
        the second translator 0x609e2d0 (by contract).
    error_status_builder(code, msg1, msg2) -> Status: the
        two-slice Status builder 0x61cf670 (by contract).

    config_options is a dict; its "byte_1" field is the byte at
    config_options+1 the host reads in the Status normalization
    branch.
    """
    # pthread_once over 0x6508928 runs the initializer 0x61ccfa0
    # before anything else; the model takes the registry as already
    # initialized.
    trans_status, translated = translator(config_options, name, dest.obj)
    if trans_status.code != 0:
        return status_move(out, trans_status)
    if not translated:
        # Empty translated name: release the destination and return
        # an empty Status.
        dest.release()
        out.code, out.subcode, out.state = 0, 0, None
        return out
    functor = find_registry(registry, translated)
    intermediate = Status()
    if functor is None:
        # No registered factory: code 3 with the translated name.
        intermediate = error_status_builder(
            3, b"Could not load SliceTransform", translated)
        return _normalize(out, intermediate, config_options, dest,
                          second_translator)
    obj_slot = {"obj": None}
    detail = {"text": None}
    created = functor(translated, obj_slot, detail)
    if not created:
        if detail["text"]:
            intermediate = error_status_builder(4, detail["text"], translated)
        else:
            intermediate = error_status_builder(
                4, b"Could not load SliceTransform", translated)
        return _normalize(out, intermediate, config_options, dest,
                          second_translator)
    if obj_slot["obj"] is None:
        intermediate = error_status_builder(
            4, b"Cannot make a shared SliceTransform from unguarded one ",
            translated)
        return _normalize(out, intermediate, config_options, dest,
                          second_translator)
    # Install: allocate a 0x18-byte control block with packed counts
    # 0x100000001 and the _Sp_counted_ptr<const SliceTransform*>
    # table, install {object, control} into dest, release the old
    # dest control, and write an empty Status.
    old = dest.control
    dest.obj = obj_slot["obj"]
    dest.control = CountedBase(use=1, weak=1, table=CONTROL_TABLE)
    if old is not None:
        old.release(True, lambda c: c._dispose())
    intermediate = Status()
    return _normalize(out, intermediate, config_options, dest,
                      second_translator)


def _normalize(out, intermediate, config_options, dest, second_translator):
    """The host's Status normalization branch (0x61ca7ae).

    Code 3 with config_options+1 set: reset to empty. Code 0:
    call the second translator, then move the result out. Any other
    code: move the intermediate Status out unchanged.
    """
    if intermediate.code == 3 and config_options.get("byte_1"):
        out.code, out.subcode, out.state = 0, 0, None
        return out
    if intermediate.code == 0:
        result = second_translator(intermediate, config_options, dest.obj,
                                   dest.obj)
        return status_move(out, result)
    return status_move(out, intermediate)


def default_init(registry):
    """The pthread_once initializer 0x61ccfa0.

    Builds an empty string, calls the registry-mutex getter
    0x61f8b60 and the register helper 0x61cbd50 (both by contract),
    which registers the default SliceTransform factory in the
    registry. The helper internals are open; the model records the
    registration as a default entry whose predicate always matches
    and whose factory creates a default object.
    """
    def default_factory(name, obj_slot, detail):
        obj_slot["obj"] = "default-slice-transform"
        return True

    node = None
    for type_name, entries in registry.buckets:
        if type_name == TYPE_NAME:
            node = entries
            break
    if node is None:
        node = []
        registry.buckets.append((TYPE_NAME, node))
    node.append((lambda key: True, default_factory))
    return TYPE_NAME
