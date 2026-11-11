"""Model of the MockFileSystem option-group vector (node #115).

Pinned by research/work-items/RE-001-mockfs-group-115/:
rocksdb::Configurable::RegisterOptions (0x6099ce0) appends one 0x30-byte
record {std::string name; void* base; unordered_map* map} to the vector
at owner+0x08 (begin +0x08, end +0x10, capacity-end +0x18). The
MockFileSystem ctor (0x6028a60) registers exactly one group: the
empty-name group (base owner+0x90, the supports_direct_io bool member,
map 0x65058e0, exactly one entry: key "supports_direct_io", type 0 =
bool, verification 0, flags 0, offset 0, no callbacks). The name is
empty, so it takes the SSO path in the builder; the vector starts
empty (zeroed by base ctor 0x5fe7080), so the registration is the only
element and the vector grows 0 -> 1 (capacity rule per #3257: 1 for an
empty vector, else min(2*size, MAX_SIZE), MAX_SIZE = (2**63 - 1) // 48).
"""

SSO_LIMIT = 15
ELEMENT_SIZE = 0x30
MAX_SIZE = (2**63 - 1) // 48

MOCKFS_MAP = 0x65058E0
MOCKFS_ENTRIES = 1
MOCKFS_TYPE = 0  # bool, per merged RE-001-optiontypeinfo-mismatches-115
OBJECT_SIZE = 0x98


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


class MockFileSystem:
    """The 0x98-byte object built by the ctor 0x6028a60.

    Layout: vtable +0x00, group vector +0x08..+0x18, mutex +0x20,
    files map +0x50 (std::map), clock shared_ptr +0x78, raw clock
    pointer +0x88, supports_direct_io bool +0x90.
    """

    def __init__(self, supports_direct_io: bool):
        self.supports_direct_io = supports_direct_io
        self.groups = GroupVector()
        self.groups.register("", 0x90, MOCKFS_MAP, MOCKFS_ENTRIES)

    @property
    def object_size(self) -> int:
        return OBJECT_SIZE


def build_mockfs(supports_direct_io: bool = True) -> MockFileSystem:
    """The registrations behind one MockFileSystem (0x6028a60).

    The vector starts empty (zeroed by base ctor 0x5fe7080), so the
    single call 0x6028b3a grows it 0 -> 1: ("", owner+0x90, 0x65058e0).
    Both creators pass bool=true (invoker 0x5fe58b0, MockEnv::Create
    0x6028d80).
    """
    return MockFileSystem(supports_direct_io)


def supports_direct_io_entry() -> MapEntry:
    """The single entry of map 0x65058e0 (static initializer 0x6029d10).

    Pack 0x0 at record+0xa8: type 0 (bool), verification 0.
    Flags 0x0 at record+0xb0. Offset 0, no callbacks.
    """
    return MapEntry("supports_direct_io", 0x0, 0x0, 0, False)
