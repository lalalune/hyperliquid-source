"""Model of node #115's encryption-provider dispatch factory 0x5ffabd0
(slot 21 of the CTREncryptionProvider vtable) and its registry
dispatcher 0x5ffa710.

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The factory 0x5ffabd0 takes (Status* out, holder, name, block_size). If
the holder's cipher slot (+0x20) is already occupied it returns
kNotSupported "Cannot add keys to CTREncryptionProvider". If the name is
"ROT13" it builds a 0x28-byte ROT13BlockCipher in place (vtable 0x64cfea0,
block_size at +0x20), registers the group "ROT13BlockCipherOptions" with
the block_size map 0x65052c0, wraps the cipher in a 0x18-byte non-inplace
shared_ptr control block (vtable 0x64d0128, counts (1,1)) and stores it
into the holder, releasing the old cipher. Otherwise it copies the name
into a stack string, default-inits a ConfigOptions with 0x60bb890, and
delegates to the registry dispatcher 0x5ffa710, which pthread_once-inits
the provider registry map 0x6505278, configures the provider through the
options-map host 0x609e510, and either resets the cipher slot or
dispatches to the registry factory 0x5ff9fe0. The factory has no direct
E8 caller and no lea site: it is reached only through vtable slot 21.
"""

FACTORY = 0x5FFABD0
DISPATCHER = 0x5FFA710
WRAPPER = 0x5FFAE10
TWIN_DISPATCHER = 0x5FFBA10
TWIN_WRAPPER = 0x5FFBDE0
REG_DISPATCH = 0x5FF9FE0
REG_INIT = 0x5FF9C50
CONFIG_INIT = 0x60BB890
STR_CTOR = 0x5FF0300
CONFIGURE_HOST = 0x609E510
NULL_CONFIGURE = 0x609E2D0
REGISTER_OPTIONS = 0x6099CE0

CIPHER_SIZE = 0x28
CONTROL_SIZE = 0x18
VT_ROT13 = 0x64CFEA0
VT_CTRL = 0x64D0128
VT_CTR = 0x64CFFB0
MAP_BLOCK = 0x65052C0
MAP_REGISTRY = 0x6505278

GROUP_NAME = "ROT13BlockCipherOptions"
GATE_MESSAGE = "Cannot add keys to CTREncryptionProvider"
RESET_MESSAGE = "Cannot reset object "

TYPEINFO_CTR = "N7rocksdb21CTREncryptionProviderE"
TYPEINFO_ROT13 = "*N7rocksdb12_GLOBAL__N_116ROT13BlockCipherE"
TYPEINFO_CTRL = (
    "*St15_Sp_counted_ptrIPN7rocksdb12_GLOBAL__N_1"
    "16ROT13BlockCipherELN9__gnu_cxx12_Lock_policyE2EE"
)

# CTREncryptionProvider vtable slots pinned by this packet.
CTR_VTABLE_SLOTS = {
    0: 0x5FF2F00, 1: 0x5FF30B0, 9: 0x609D0E0, 10: 0x60986B0,
    12: 0x609DE80, 13: 0x609D980, 15: 0x5D32A30, 16: 0x5FF1030,
    17: 0x5D2CA00, 18: 0x5D2CA10, 19: 0x5FEFA30, 20: 0x5FF5140,
    21: 0x5FFABD0, 22: 0x5FF3890, 23: 0x5FF02E0, 24: 0x5FEFA40,
    25: 0x5FF49B0,
}
# _Sp_counted_ptr<ROT13BlockCipher> control-block vtable slots.
CTRL_VTABLE_SLOTS = [0x5FEFB60, 0x5FEFD10, 0x5FF0580, 0x5FEFD20, 0x5FEFC60]

MAP_BLOCK_ENTRIES = {
    "block_size": {"type": 22, "verification": 1, "flags": 0x400,
                   "offset": 0},
}

# Status codes (rocksdb::Status::Code).
K_OK = 0
K_NOT_FOUND = 1
K_NOT_SUPPORTED = 3


class Status:
    """A 16-byte Status: code + message."""

    def __init__(self, code=K_OK, message=""):
        self.code = code
        self.message = message

    def is_ok(self):
        return self.code == K_OK


class ControlBlock:
    """A shared_ptr control block: use/weak counts."""

    def __init__(self, use_count=1, weak_count=1):
        self.use_count = use_count
        self.weak_count = weak_count
        self.destroyed = False
        self.vtable = None

    def release(self):
        self.use_count -= 1
        if self.use_count == 0:
            self.destroyed = True
            return True
        return False


class SharedPtr:
    """A shared_ptr: (ptr, control)."""

    def __init__(self, ptr=None, control=None):
        self.ptr = ptr
        self.control = control

    def is_null(self):
        return self.ptr is None


class ROT13BlockCipher:
    """A 0x28-byte ROT13BlockCipher (vtable 0x64cfea0)."""

    SIZE = 0x28

    def __init__(self, block_size):
        self.vtable = VT_ROT13
        self.block_size = block_size  # stored at +0x20 (8-byte store)
        self.groups_registered = []

    def register_group(self, name, options_map):
        self.groups_registered.append((name, options_map))


class Holder:
    """The holder whose cipher shared_ptr lives at +0x20/+0x28."""

    def __init__(self, cipher=None):
        self.cipher = cipher if cipher is not None else SharedPtr()

    def store_cipher(self, new):
        old = self.cipher
        self.cipher = new
        if old.control is not None and not old.is_null():
            old.control.release()
        return old


def dispatch(name, block_size, holder):
    """The 0x5ffabd0 dispatch factory.

    Returns (status, outcome) where outcome is "gate-error", "rot13" or
    "delegate". On the ROT13 path the holder receives the new cipher and
    the outcome carries the cipher and its control block.
    """
    if not holder.cipher.is_null():
        return (Status(K_NOT_SUPPORTED, GATE_MESSAGE), "gate-error")
    if name == "ROT13":
        cipher = ROT13BlockCipher(block_size)
        cipher.register_group(GROUP_NAME, MAP_BLOCK)
        control = ControlBlock(use_count=1, weak_count=1)
        control.vtable = VT_CTRL
        wrapped = SharedPtr(cipher, control)
        holder.store_cipher(wrapped)
        return (Status(K_OK), ("rot13", cipher, control))
    return (Status(K_OK), ("delegate", name, block_size))


class ConfigOptions:
    """ConfigOptions as default-initialized by 0x60bb890."""

    def __init__(self):
        self.flags_word = 0x01010100  # +0x00
        self.plus_0x10 = 1
        self.delimiter = ";"  # +0x18 (0x3b)
        self.plus_0x28 = 0
        self.plus_0x2c = 0xFF
        self.plus_0x30 = 0x80000
        self.byte_0x01 = 0x01  # second byte of the flags word

    def byte_01(self):
        return self.byte_0x01


def string_from_cstr(text):
    """The 0x5ff0300 string ctor: SSO for <= 15 bytes, heap above."""
    return {"text": text, "heap": len(text) > 15}


def registry_dispatcher(name, opts, holder, configure):
    """The 0x5ffa710 registry dispatcher, driven by a configure outcome.

    `configure` is a dict with keys: status (Status from 0x609e510),
    out_name (str, "" when empty) and map_nonempty (bool). Returns
    (status, outcome) where outcome is one of "configure-error",
    "factory-dispatch", "reset-error", "reset-ok".
    """
    status = configure["status"]
    if not status.is_ok():
        return (status, "configure-error")
    if configure["out_name"]:
        return (Status(K_OK), ("factory-dispatch", configure["out_name"]))
    if configure["map_nonempty"]:
        return (Status(K_NOT_SUPPORTED, RESET_MESSAGE), "reset-error")
    holder.cipher = SharedPtr()
    return (Status(K_OK), "reset-ok")


def dispatcher_factory_tail(code, opts_byte_01):
    """The 0x5ffa710 factory-dispatch tail after 0x5ff9fe0 returns.

    Returns "swallow-to-ok" when a code-3 result is swallowed to kOk,
    "null-configure" when a code-0 result falls through to 0x609e2d0,
    and "propagate" otherwise.
    """
    if opts_byte_01 != 0 and code == 3:
        return "swallow-to-ok"
    if opts_byte_01 == 0 and code == 0:
        return "null-configure"
    return "propagate"


def wrapper_id_guard(rcx_count, rcx_name_starts_with_id, r8_plus_0x08):
    """The 0x5ffae10 'id'-guard wrapper.

    Returns "clear" when rcx+0x08 == 2, the rcx name starts with "id"
    (0x6469) and r8+0x08 == 0; otherwise "forward" to the dispatcher.
    """
    if (rcx_count == 2 and rcx_name_starts_with_id
            and r8_plus_0x08 == 0):
        return "clear"
    return "forward"
