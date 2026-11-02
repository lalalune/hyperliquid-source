"""Model of node #94 0x51601c0: the BlockCache entry-name table initializer.

The window (FDE 0x51601c0..0x516054e, 910 bytes, no padding to the
next FDE 0x516054e) is a static initializer reached through
.init_array slot 44 (vaddr 0x5662eb0, R_X86_64_RELATIVE to
0x51601c0), not through a direct call. At load it fills two tables
of 14 std::string records each, stride 0x20 bytes (pointer, length,
16 unused bytes), by calling the string-from-C-string routine
0x515f7a0 once per name, and it registers the table destructor
0x515f870 with __cxa_atexit once per table, with __dso_handle
0x577a660. The first table's destructor registration happens after
its 14 assignments (0x51602e3); the second table's registration is
the tail call at 0x51603f9, so registration order is first table,
then second table.

String layout, as the callee uses it: pointer at +0x00, length at
+0x08, inline buffer or heap capacity at +0x10. The callee's arms:
a null source throws logic_error with the message at 0x7e0c18
("basic_string: construction from null is not valid"); a length of
1 copies the single byte directly into the inline buffer; lengths
up to 15 stay inline (the buffer address itself is the pointer);
longer strings go through _M_create for a heap buffer. The exact
heap capacity _M_create allocates is not pinned here -- the model
records only that the pointer is a heap buffer, the length is the
source length, and a NUL terminator sits at pointer + length.

The destructor walks a table backwards (entry 13 down to entry 0)
and, for each entry whose pointer differs from its own +0x10 inline
buffer address, frees the heap buffer with operator delete[] of
length + 1 bytes. Inline entries are left alone.

The first table (base 0x578c2e0) is the name table the BlockCache
report formatter 0x514f770 reads (own packet PR #1677); its 14
entries are the PascalCase names. The second table (base
0x578c120) holds the kebab-case spellings of the same 14 entries,
in the same order. Which consumers read the second table is not
pinned in this packet.
"""

# The 14 entry names, in table order. First table: PascalCase.
# Second table: kebab-case, same order.
PASCAL_NAMES = [
    "DataBlock",
    "FilterBlock",
    "FilterMetaBlock",
    "DeprecatedFilterBlock",
    "IndexBlock",
    "OtherBlock",
    "WriteBuffer",
    "CompressionDictionaryBuildingBuffer",
    "FilterConstruction",
    "BlockBasedTableReader",
    "FileMetadata",
    "BlobValue",
    "BlobCache",
    "Misc",
]

KEBAB_NAMES = [
    "data-block",
    "filter-block",
    "filter-meta-block",
    "deprecated-filter-block",
    "index-block",
    "other-block",
    "write-buffer",
    "compression-dictionary-building-buffer",
    "filter-construction",
    "block-based-table-reader",
    "file-metadata",
    "blob-value",
    "blob-cache",
    "misc",
]

FIRST_TABLE_BASE = 0x578C2E0
SECOND_TABLE_BASE = 0x578C120
ENTRY_STRIDE = 0x20
ENTRY_COUNT = 14
SSO_LIMIT = 15
INIT_ARRAY_SLOT = 0x5662EB0
INIT_ARRAY_INDEX = 44
DSO_HANDLE = 0x577A660


class NullStringError(ValueError):
    """Raised when the source C string is null (logic_error)."""


class CxxString:
    """One std::string record, as built by 0x515f7a0."""

    def __init__(self, source):
        if source is None:
            raise NullStringError(
                "basic_string: construction from null is not valid")
        self.value = bytes(source)
        self.length = len(self.value)
        # Length 1 copies the byte directly; lengths up to 15 stay
        # inline; longer strings take a heap buffer. The observable
        # result is the same in all three arms: value, length, and a
        # NUL terminator at value + length.
        self.storage = "inline" if self.length <= SSO_LIMIT else "heap"
        self.terminated = self.value + b"\x00"
        self.disposed = False

    def __repr__(self):
        return "CxxString(%r, %s)" % (self.value.decode(), self.storage)


class EntryNameTable:
    """One 14-entry table of string records at a fixed base."""

    def __init__(self, base, names):
        self.base = base
        self.entries = [CxxString(name.encode()) for name in names]

    def entry_address(self, index):
        return self.base + index * ENTRY_STRIDE

    def names(self):
        return [entry.value.decode() for entry in self.entries]

    def destroy(self):
        """Run 0x515f870 over this table.

        Returns the indices freed, in the order the destructor
        visits them: backwards, heap entries only.
        """
        freed = []
        for index in range(ENTRY_COUNT - 1, -1, -1):
            entry = self.entries[index]
            if entry.storage == "heap" and not entry.disposed:
                entry.disposed = True
                freed.append(index)
        return freed


def initialize():
    """Run the 0x51601c0 initializer.

    Returns (first_table, second_table, registrations) where
    registrations is the __cxa_atexit order: one entry per table,
    each (destructor_address, table_base, dso_handle).
    """
    first = EntryNameTable(FIRST_TABLE_BASE, PASCAL_NAMES)
    registrations = [(0x515F870, FIRST_TABLE_BASE, DSO_HANDLE)]
    second = EntryNameTable(SECOND_TABLE_BASE, KEBAB_NAMES)
    registrations.append((0x515F870, SECOND_TABLE_BASE, DSO_HANDLE))
    return first, second, registrations
