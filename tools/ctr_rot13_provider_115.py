"""Model of node #115's CTR/ROT13 provider factories 0x5ff6a00 / 0x5ff6d60
and the CTREncryptionProvider holder init 0x5ff6880.

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The two factories are registry entries built by 0x5ff88c0: "1://test"
-> 0x5ff6a00 and "CTR" -> 0x5ff6d60. Both build the same two objects:

  * a 0x38-byte _Sp_counted_ptr_inplace<ROT13BlockCipher> (vtable
    0x64d0160): use_count 1 / weak_count 1 from the (1, 1) qword at
    0x459b20, with the ROT13BlockCipher in place at +0x10 (vtable
    0x64cfea0, block_size 32 at +0x30);
  * a 0x30-byte CTREncryptionProvider (vtable 0x64cffb0) holding an
    aliasing shared_ptr<BlockCipher> at +0x20/+0x28: ptr points at the
    in-place cipher, control is the in-place control block itself.

The factory registers the group "ROT13BlockCipherOptions" with the static
map 0x65052c0 (one entry, "block_size", type 22, verification 1, flags
0x400, offset 0) and the provider init 0x5ff6880 registers the group
"Cipher" with the static map 0x6505280 (one entry, "cipher", same pack
and flags). The "CTR" factory 0x5ff6d60 builds the ROT13 provider only
when the spec ends with "://test" (ends_with via 0x61d1390); otherwise
it builds an empty Cipher holder whose cipher is null.

Replacing the provider in the out slot destroys the old one: vtable
slot 1 of the old provider is compared against the CTREncryptionProvider
deleting destructor 0x5ff30b0 (held in GOT slot 0x64ed998). If it differs,
the derived deleting destructor runs instead; if it is the base one, the
destruction is inlined: vtable reset to 0x64cffb0, cipher shared_ptr
released, vtable reset to 0x64d3430 (rocksdb::Configurable), the
option-groups vector destroyed element by element, then the object
freed (sized delete, 0x30 bytes).
"""

DEFAULT_BLOCK_SIZE = 32
TEST_SUFFIX = "://test"

ROT13_GROUP_NAME = "ROT13BlockCipherOptions"
ROT13_GROUP_MAP = 0x65052C0
CIPHER_GROUP_NAME = "Cipher"
CIPHER_GROUP_MAP = 0x6505280

WRAPPER_SIZE = 0x38
PROVIDER_SIZE = 0x30
VTABLE_INPLACE = 0x64D0160
VTABLE_CTR = 0x64CFFB0
VTABLE_CONFIG = 0x64D3430
VTABLE_ROT13 = 0x64CFEA0
DTOR_CTR = 0x5FF30B0

MAP_ENTRIES = {
    0x65052C0: {
        "block_size": {"type": 22, "verification": 1, "flags": 0x400,
                       "offset": 0},
    },
    0x6505280: {
        "cipher": {"type": 22, "verification": 1, "flags": 0x400,
                   "offset": 0},
    },
}

REGISTRY = {
    "1://test": {"factory": 0x5FF6A00, "paired": 0x5FEFA80},
    "CTR": {"factory": 0x5FF6D60, "paired": 0x5FEFA50},
    "ROT13": {"factory": 0x5FF7120, "paired": 0x5FEFAB0},
}


class SharedPtr:
    """A shared_ptr: (ptr, control). The control carries use/weak counts."""

    def __init__(self, ptr, control):
        self.ptr = ptr
        self.control = control

    def is_null(self):
        return self.ptr is None and self.control is None

    def copy(self):
        if self.control is not None:
            self.control.use_count += 1
        return SharedPtr(self.ptr, self.control)

    def release(self):
        """Release one reference; returns True when the control dies."""
        if self.control is None:
            return False
        self.control.use_count -= 1
        if self.control.use_count == 0:
            self.control.destroy()
            return True
        return False


class InplaceRot13Control:
    """The 0x38-byte _Sp_counted_ptr_inplace<ROT13BlockCipher>."""

    def __init__(self, block_size=DEFAULT_BLOCK_SIZE):
        self.vtable = VTABLE_INPLACE
        self.size = WRAPPER_SIZE
        self.use_count = 1
        self.weak_count = 1
        self.cipher = {
            "vtable": VTABLE_ROT13,
            "block_size": block_size,
        }
        self.destroyed = False

    def destroy(self):
        self.destroyed = True
        self.cipher = None


class CTREncryptionProvider:
    """The 0x30-byte object built by 0x5ff6880."""

    def __init__(self, cipher_ptr):
        self.vtable = VTABLE_CTR
        self.size = PROVIDER_SIZE
        # Configurable group-vector triple, empty: begin/end/capacity.
        self.groups = []
        # The Cipher option group, registered by 0x5ff6880.
        self.groups.append({
            "name": CIPHER_GROUP_NAME,
            "base_offset": 0x20,
            "map": CIPHER_GROUP_MAP,
            "entries": dict(MAP_ENTRIES[CIPHER_GROUP_MAP]),
        })
        self.cipher = cipher_ptr
        # Deleting destructor (vtable slot 1); the base one is 0x5ff30b0.
        self.deleting_dtor = DTOR_CTR
        self.destroyed = False
        self.destroy_trace = []


def build_rot13_wrapper(block_size=DEFAULT_BLOCK_SIZE):
    """Mirror the wrapper construction shared by both factories."""
    wrapper = InplaceRot13Control(block_size)
    # The factory registers ROT13BlockCipherOptions on the in-place cipher.
    group = {
        "name": ROT13_GROUP_NAME,
        "base_offset": 0x30,
        "map": ROT13_GROUP_MAP,
        "entries": dict(MAP_ENTRIES[ROT13_GROUP_MAP]),
    }
    return wrapper, group


def init_provider(cipher_ptr):
    """Mirror 0x5ff6880: build the 0x30-byte provider around a shared_ptr."""
    return CTREncryptionProvider(cipher_ptr)


def destroy_provider(provider):
    """Mirror the old-provider destruction in 0x5ff6a00 / 0x5ff6d60.

    Returns the ordered list of steps taken. A derived deleting
    destructor (anything other than 0x5ff30b0) is called instead of the
    inline steps.
    """
    trace = []
    if provider is None:
        return trace
    if provider.deleting_dtor != DTOR_CTR:
        trace.append(("call_derived_dtor", provider.deleting_dtor))
        provider.destroyed = True
        provider.destroy_trace = trace
        return trace
    trace.append(("vtable_reset", VTABLE_CTR))
    if provider.cipher is not None:
        provider.cipher.release()
        trace.append(("release_cipher_shared_ptr", True))
    trace.append(("vtable_reset", VTABLE_CONFIG))
    for group in provider.groups:
        trace.append(("destroy_group", group["name"]))
    provider.groups = []
    trace.append(("free_object", PROVIDER_SIZE))
    provider.destroyed = True
    provider.destroy_trace = trace
    return trace


def _replace(out_slot, provider):
    """Mirror the out-slot swap: store the new provider, destroy the old."""
    old = out_slot[0]
    out_slot[0] = provider
    if old is not None:
        destroy_provider(old)
    return provider


def create_provider_1_test(out_slot):
    """Mirror factory 0x5ff6a00 (registry name "1://test").

    Unconditionally builds the ROT13 provider: the in-place wrapper,
    the ROT13BlockCipherOptions registration, the aliasing shared_ptr
    handoff to 0x5ff6880, and the out-slot swap. The factory's own
    wrapper reference is released after the handoff.
    """
    wrapper, group = build_rot13_wrapper()
    mine = SharedPtr(wrapper.cipher, wrapper)
    provider = init_provider(mine.copy())
    mine.release()
    provider.rot13_group = group
    provider.wrapper = wrapper
    return _replace(out_slot, provider)


def ends_with_test(spec):
    """Mirror the 0x5ff6d60 gate: ends_with(spec, "://test")."""
    return spec.endswith(TEST_SUFFIX)


def create_provider_ctr(spec, out_slot):
    """Mirror factory 0x5ff6d60 (registry name "CTR").

    Spec ending with "://test" -> the ROT13 provider, exactly as
    0x5ff6a00 builds it. Any other spec -> an empty Cipher holder whose
    cipher shared_ptr is null; the provider is still stored and the old
    provider destroyed the same way.
    """
    if ends_with_test(spec):
        return create_provider_1_test(out_slot)
    provider = init_provider(SharedPtr(None, None))
    return _replace(out_slot, provider)
