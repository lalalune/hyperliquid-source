"""Model of the ChrootFileSystem option-group vector (node #115).

Pinned by research/work-items/RE-001-chrootfs-group-115/:
rocksdb::Configurable::RegisterOptions (0x6099ce0) appends one 0x30-byte
record {std::string name; void* base; unordered_map* map} to the vector
at owner+0x08 (begin +0x08, end +0x10, capacity-end +0x18). The
ChrootFileSystem ctor (0x5feeab0) registers exactly one group:
"chroot_dir" (base owner+0x30, the chroot-dir std::string member, map
0x6505240, exactly one entry: key "chroot_dir", type 9 = string,
verification 0, flags 0, offset 0, no callbacks). The name is 10 chars,
so it takes the SSO path in the builder; the vector already holds the
base class's empty-name group (FileSystemWrapper ctor 0x5fe7210, base
owner+0x20, map 0x65051e0, pinned by open PR #4398), so the
chroot_dir registration is the second element and the vector grows
1 -> 2 (capacity rule per #3257: 1 for an empty vector, else
min(2*size, MAX_SIZE), MAX_SIZE = (2**63 - 1) // 48).
"""

SSO_LIMIT = 15
ELEMENT_SIZE = 0x30
MAX_SIZE = (2**63 - 1) // 48

BASE_MAP = 0x65051E0
CHROOT_MAP = 0x6505240
CHROOT_ENTRIES = 1
CHROOT_TYPE = 9  # string, per merged RE-001-optiontypeinfo-mismatches-115


class OptionGroup:
    """One 0x30-byte element: name string + options base + map pointer."""

    def __init__(self, name: str, base_offset: int, map_addr: int,
                 map_entries: int | None):
        self.name = name
        self.base_offset = base_offset
        self.map_addr = map_addr
        self.map_entries = map_entries

    @property
    def heap_backed(self) -> bool:
        """libstdc++ SSO: names longer than 15 chars live on the heap."""
        return len(self.name) > SSO_LIMIT

    @property
    def element_bytes(self) -> int:
        return ELEMENT_SIZE

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (f"OptionGroup(name={self.name!r}, base=+{self.base_offset:#x}, "
                f"map={self.map_addr:#x}, entries={self.map_entries})")


class MapEntry:
    """One OptionTypeInfo map entry (key + pack/flags/offset/callbacks)."""

    def __init__(self, key: str, pack: int, flags: int, offset: int,
                 callbacks: bool):
        self.key = key
        self.pack = pack
        self.flags = flags
        self.offset = offset
        self.callbacks = callbacks

    @property
    def option_type(self) -> int:
        """Low dword of the pack is the OptionType."""
        return self.pack & 0xFFFFFFFF

    @property
    def verification(self) -> int:
        """High dword of the pack is the OptionVerification."""
        return (self.pack >> 32) & 0xFFFFFFFF


class GroupVector:
    """The std::vector<OptionGroup> triple at owner+0x08..+0x18."""

    def __init__(self):
        self.groups: list[OptionGroup] = []
        self.capacity = 0

    @property
    def size(self) -> int:
        return len(self.groups)

    @property
    def byte_size(self) -> int:
        return self.size * ELEMENT_SIZE

    def register(self, name: str, base_offset: int, map_addr: int,
                 map_entries: int | None) -> OptionGroup:
        """rocksdb::Configurable::RegisterOptions append (0x6099ce0).

        Growth path (end == capacity-end) reallocates first; otherwise
        the record is written into the slot at end. Either way end
        advances by exactly one 0x30-byte element.
        """
        group = OptionGroup(name, base_offset, map_addr, map_entries)
        if self.size == self.capacity:
            self.capacity = 1 if self.capacity == 0 else min(
                2 * self.size, MAX_SIZE)
        self.groups.append(group)
        return group


def build_chrootfs() -> GroupVector:
    """The registrations behind one ChrootFileSystem (0x5feeab0).

    Base first, FileSystemWrapper ctor 0x5fe7210 call 0x5fe7292
    (#4398): ("", owner+0x20, 0x65051e0). Then this packet, host call
    0x5feeb6a: ("chroot_dir", owner+0x30, 0x6505240). The vector starts
    empty (zeroed by base ctor 0x5fe7080), so the first call grows it
    0 -> 1 and the second grows it 1 -> 2.
    """
    vec = GroupVector()
    vec.register("", 0x20, BASE_MAP, None)
    vec.register("chroot_dir", 0x30, CHROOT_MAP, CHROOT_ENTRIES)
    return vec


def chroot_dir_entry() -> MapEntry:
    """The single entry of map 0x6505240 (static initializer 0x5fef080).

    Pack 0x9 at record+0xa8: type 9 (string), verification 0.
    Flags 0x0 at record+0xb0. Offset 0, no callbacks.
    """
    return MapEntry("chroot_dir", 0x9, 0x0, 0, False)
