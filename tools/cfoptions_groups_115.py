"""Model of the ConfigurableCFOptions option-group vector (node #115).

Pinned by research/work-items/RE-001-cfoptions-groups-115/:
rocksdb::Configurable::RegisterOptions (0x6099ce0) appends one 0x30-byte
record {std::string name; void* base; unordered_map* map} to the vector
at owner+0x08 (begin +0x08, end +0x10, capacity-end +0x18). The
ConfigurableCFOptions ctor (0x6086e00) registers exactly two groups, in
order: "MutableCFOptions" (base owner+0x20, map 0x6506b20, 62 entries)
then "ImmutableCFOptions" (base owner+0x218, map 0x6506ae0, 31 entries).
Both names are longer than 15 chars, so both take the heap-backed
string path in the builder; the vector grows 0 -> 1 -> 2 elements
(capacity rule per #3257: 1 for an empty vector, else min(2*size,
MAX_SIZE), MAX_SIZE = (2**63 - 1) // 48).
"""

SSO_LIMIT = 15
ELEMENT_SIZE = 0x30
MAX_SIZE = (2**63 - 1) // 48

MUTABLE_MAP = 0x6506B20
MUTABLE_ENTRIES = 62
IMMUTABLE_MAP = 0x6506AE0
IMMUTABLE_ENTRIES = 31


class OptionGroup:
    """One 0x30-byte element: name string + options base + map pointer."""

    def __init__(self, name: str, base_offset: int, map_addr: int, map_entries: int):
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
                 map_entries: int) -> OptionGroup:
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


def build_cfoptions_configurable() -> GroupVector:
    """The two RegisterOptions calls of ConfigurableCFOptions (0x6086e00).

    Call 1 at 0x608749a: ("MutableCFOptions", owner+0x20, 0x6506b20).
    Call 2 at 0x6087ce8: ("ImmutableCFOptions", owner+0x218, 0x6506ae0).
    The vector starts empty (begin=end=capacity-end=0), so both calls
    take the growth path.
    """
    vec = GroupVector()
    vec.register("MutableCFOptions", 0x20, MUTABLE_MAP, MUTABLE_ENTRIES)
    vec.register("ImmutableCFOptions", 0x218, IMMUTABLE_MAP, IMMUTABLE_ENTRIES)
    return vec
