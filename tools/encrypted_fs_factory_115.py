"""Model of node #115's EncryptedFileSystemImpl factory 0x5ff6690 and the
FileSystemWrapper ctor 0x5fe7210.

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The factory 0x5ff6690 builds a 0x40-byte
rocksdb::(anonymous namespace)::EncryptedFileSystemImpl (vtable 0x64cfca0):
the FileSystemWrapper ctor 0x5fe7210 stores the caller-supplied wrapped
FileSystem shared_ptr at +0x20/+0x28 and registers the empty-named group
with the static map 0x65051e0 (one entry, "target", type 22, verification
1, flags 0x2400, offset 0); the factory itself stores the caller-supplied
BlockCipher shared_ptr at +0x30/+0x38 and registers the group
"EncryptionProvider" with the static map 0x6505300 (one entry,
"provider", type 22, verification 1, flags 0x400, offset 0). Replacing
the provider in the out slot destroys the old object through its vtable
slot 1. The factory is reached only from the registered factory
0x5fe7a20, which passes two empty shared_ptrs, so the registered
"EncryptedFileSystem" starts blank and is configured later through the
"target" and "provider" options. The factories are registered by
RegisterBuiltinFileSystems 0x5febf50 alongside TimedFS,
ReadOnlyFilesystem, CountedFileSystem and MemoryFileSystem.
"""

FACTORY = 0x5FF6690
WRAPPER_CTOR = 0x5FE7210
FS_CTOR = 0x5FE7080
GROUP_DTOR = 0x5FE70B0
DTOR = 0x5FF3000
DEL_DTOR = 0x5FF3050
REG_FACTORY = 0x5FE7A20
NAME_FN = 0x5FEF930
RECORD_CTOR = 0x5FE7EE0
STATIC_INIT = 0x5FEB760
BUILDER = 0x5FEBF50
MANAGER = 0x5FE5700

OBJECT_SIZE = 0x40
VTABLE_IMPL = 0x64CFCA0
VTABLE_WRAPPER = 0x64CF200
VTABLE_FS = 0x64CF008
VTABLE_CONFIG = 0x64D3430

GROUP_NAME = "EncryptionProvider"
GROUP_MAP = 0x6505300
TARGET_MAP = 0x65051E0

MAP_ENTRIES = {
    0x6505300: {
        "provider": {"type": 22, "verification": 1, "flags": 0x400,
                     "offset": 0},
    },
    0x65051E0: {
        "target": {"type": 22, "verification": 1, "flags": 0x2400,
                   "offset": 0},
    },
}

REGISTRY = {
    "TimedFS": {"factory": 0x5FE74A0, "manager": 0x5FE56A0},
    "ReadOnlyFilesystem": {"factory": 0x5FE7720, "manager": 0x5FE56D0},
    "EncryptedFileSystem": {"factory": 0x5FE7A20, "manager": 0x5FE5700},
    "CountedFileSystem": {"factory": 0x5FE75E0, "manager": 0x5FE5730},
    "MemoryFileSystem": {"factory": 0x5FE58B0, "manager": 0x5FE5760},
}

MANAGER_TYPEINFO = 0x64CEDA8  # the RegisterBuiltinFileSystems lambda

# GOT callback pair shared by the option records (#4379).
CALLBACKS = (0x5FD5460, 0x5FD7470)


class ControlBlock:
    """A shared_ptr control block: use/weak counts."""

    def __init__(self, use_count=1, weak_count=1):
        self.use_count = use_count
        self.weak_count = weak_count
        self.destroyed = False

    def bump_use(self):
        # Plain addl when __libc_single_threaded, else lock addl;
        # the outcome is the same either way.
        self.use_count += 1

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
        return self.ptr is None and self.control is None

    def copy(self):
        if self.control is not None:
            self.control.bump_use()
        return SharedPtr(self.ptr, self.control)

    def release(self):
        if self.control is None:
            return False
        return self.control.release()


class OptionRecord:
    """One OptionTypeInfo record, as built by the record ctor 0x5fe7ee0."""

    def __init__(self, offset, verification, flags):
        # The ctor hardcodes type 22 and ORs 0x400 into the flags.
        self.offset = offset
        self.type = 22
        self.verification = verification
        self.flags = flags | 0x400
        self.callbacks = CALLBACKS

    def pack(self):
        return (self.verification << 32) | self.type


def build_target_record():
    """The 'target' record built by the static init 0x5feb760."""
    return OptionRecord(offset=0, verification=1, flags=0x2000)


def build_provider_record():
    """The 'provider' record built by the static init 0x5ff7c90."""
    return OptionRecord(offset=0, verification=1, flags=0x0000)


class FileSystemWrapper:
    """The FileSystemWrapper subobject built by 0x5fe7210."""

    def __init__(self, wrapped):
        self.vtable = VTABLE_WRAPPER
        self.size = OBJECT_SIZE
        # FileSystem ctor 0x5fe7080: vtable 0x64cf008, group vector zeroed.
        self.fs_vtable = VTABLE_FS
        self.groups = []
        # Wrapper ctor: copy the wrapped shared_ptr to +0x20/+0x28.
        self.wrapped_fs = wrapped.copy() if wrapped is not None else SharedPtr()
        # Register the empty-named group with the target map.
        self.groups.append(("", TARGET_MAP))

    def name(self):
        # Slot 14 is pure virtual in the wrapper.
        return None


class EncryptedFileSystemImpl(FileSystemWrapper):
    """The 0x40-byte object built by the factory 0x5ff6690."""

    def __init__(self, wrapped, cipher):
        super().__init__(wrapped)
        self.vtable = VTABLE_IMPL
        # The factory zeroes +0x38, then copies the cipher shared_ptr
        # to +0x30/+0x38 with a use-count bump.
        self.cipher = cipher.copy() if cipher is not None else SharedPtr()
        self.groups.append((GROUP_NAME, GROUP_MAP))
        self.destroyed = False
        self.destroy_log = []

    def name(self):
        # Slot 14 override 0x5fef930 returns the literal 0x44470e.
        return "EncryptedFileSystem"

    def destroy(self):
        """The complete dtor 0x5ff3000: release order is cipher first."""
        self.destroy_log.append("reset vtable to impl")
        if not self.cipher.is_null():
            self.destroy_log.append("release cipher")
            self.cipher.release()
        self.destroy_log.append("reset vtable to wrapper")
        if not self.wrapped_fs.is_null():
            self.destroy_log.append("release wrapped fs")
            self.wrapped_fs.release()
        self.destroy_log.append("group dtor")
        self.groups = []
        self.destroyed = True

    def deleting_destroy(self):
        """The deleting dtor 0x5ff3050: destroy, then sized delete."""
        self.destroy()
        self.destroy_log.append(f"sized delete {OBJECT_SIZE:#x}")
        return OBJECT_SIZE


class OutSlot:
    """The out slot the factory stores into (a T* variable)."""

    def __init__(self, current=None):
        self.current = current

    def store(self, new):
        """Store the new object, destroying the old via vtable slot 1."""
        old = self.current
        self.current = new
        if old is not None:
            old.deleting_destroy()
        return old


def create_encrypted_fs(wrapped, cipher, out_slot):
    """Mirror of the factory 0x5ff6690.

    Returns (status_code, object): status 0 is kOk. The factory always
    returns kOk; the out slot holds the new object.
    """
    obj = EncryptedFileSystemImpl(wrapped, cipher)
    out_slot.store(obj)
    return 0, obj


def create_registered_encrypted_fs(out_slot, error_string, fail=False):
    """Mirror of the registered factory 0x5fe7a20.

    Passes two empty shared_ptrs to the factory. On success returns the
    object and leaves the error string untouched; on failure formats the
    Status into the error string (via 0x61cfed0) and returns the
    out-slot contents (None here).
    """
    if fail:
        error_string[0] = "Status(error)"
        return None
    _, obj = create_encrypted_fs(SharedPtr(), SharedPtr(), out_slot)
    return obj


def manager_op(op, rdi_holder, rsi=None):
    """Mirror of the std::function manager 0x5fe5700.

    op 0 stores the lambda typeinfo, op 1 stores rsi, anything else
    returns 0 without storing. Always returns 0.
    """
    if op == 0:
        rdi_holder[0] = MANAGER_TYPEINFO
    elif op == 1:
        rdi_holder[0] = rsi
    return 0
