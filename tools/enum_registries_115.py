"""Model of node #115's named-enum registries (RE-001).

The twelve .bss registries built by the static initializer
0x60c78a0: eight std::unordered_map<std::string, unsigned char>
(name -> value) and four std::map<unsigned char, std::string>
(value -> name).  Values are the as-built bytes the initializer
writes into the records -- including the CompressionType anomaly
(kZSTDNotFinalCompression = 64, kDisableCompressionOption = 255),
which disagrees with the upstream RocksDB header and is recorded
as observed, not corrected.

Parse and serialize mirror the binary's helpers:
- parse (0x60be160..0x60bea8b): name -> value, 1 on hit / 0 on miss.
  If element_count > 20 the helper takes the hash path
  (_ZSt11_Hash_bytes, seed 0xc70f6907); otherwise it linearly scans
  the element list comparing size then memcmp.  Every registry has
  at most 10 entries, so the linear path is the live one.
- serialize (fn-60ba600 cases): value -> name by a linear reverse
  scan of the element list, comparing the node value byte @+0x28;
  the first match from the end wins; no match falls through to the
  default path.
- type 14 (CompactionStopStyle) is stored as a 4-byte field in the
  options struct: its parse helper stores with a 32-bit mov and its
  serialize case loads/compares 4 bytes.  The other six named-enum
  types store one byte.

Usage: python3 -m tools.enum_registries_115
"""

# option type -> (enum name, registry address, field width in bytes)
TYPES = {
    11: ("CompactionStyle", "0x65070a0", 1),
    12: ("CompactionPri", "0x6507060", 1),
    13: ("CompressionType", "0x6507120", 1),
    14: ("CompactionStopStyle", "0x6507020", 4),
    15: ("ChecksumType", "0x6507160", 1),
    16: ("EncodingType", "0x65070e0", 1),
    24: ("Temperature", "0x6506fe0", 1),
}

# registry address -> {name: value}; as built by the initializer.
UNORDERED = {
    "0x6506fa0": {"kDisable": 0, "kFlushOnly": 1},
    "0x6506fe0": {"kUnknown": 0, "kHot": 4, "kWarm": 8, "kCold": 12},
    "0x6507020": {"kCompactionStopStyleSimilarSize": 0,
                  "kCompactionStopStyleTotalSize": 1},
    "0x6507060": {"kByCompensatedSize": 0, "kOldestLargestSeqFirst": 1,
                  "kOldestSmallestSeqFirst": 2, "kMinOverlappingRatio": 3,
                  "kRoundRobin": 4},
    "0x65070a0": {"kCompactionStyleLevel": 0,
                  "kCompactionStyleUniversal": 1,
                  "kCompactionStyleFIFO": 2, "kCompactionStyleNone": 3},
    "0x65070e0": {"kPlain": 0, "kPrefix": 1},
    "0x6507120": {"kNoCompression": 0, "kSnappyCompression": 1,
                  "kZlibCompression": 2, "kBZip2Compression": 3,
                  "kLZ4Compression": 4, "kLZ4HCCompression": 5,
                  "kXpressCompression": 6, "kZSTD": 7,
                  # As built by the initializer: 64 and 255, not the
                  # upstream header's 8 and 64 (see records.json).
                  "kZSTDNotFinalCompression": 64,
                  "kDisableCompressionOption": 255},
    "0x6507160": {"kNoChecksum": 0, "kCRC32c": 1, "kxxHash": 2,
                  "kxxHash64": 3, "kXXH3": 4},
}

# registry address -> {value: name}; the reverse maps.
ORDERED = {
    "0x65071a0": {0: "kUnknown", 4: "kHot", 8: "kWarm", 12: "kCold"},
    "0x65071e0": {0: "kCompactionStopStyleSimilarSize",
                  1: "kCompactionStopStyleTotalSize"},
    "0x6507220": {0: "kByCompensatedSize", 1: "kOldestLargestSeqFirst",
                  2: "kOldestSmallestSeqFirst", 3: "kMinOverlappingRatio",
                  4: "kRoundRobin"},
    "0x6507260": {0: "kCompactionStyleLevel",
                  1: "kCompactionStyleUniversal",
                  2: "kCompactionStyleFIFO", 3: "kCompactionStyleNone"},
}

# Hash-path threshold and seed from the parse helpers.
HASH_THRESHOLD = 20
HASH_SEED = 0xC70F6907

# Field widths (bytes) of the stored enum value per OptionType.
FIELD_BYTES = {t: w for t, (_, _, w) in TYPES.items()}


def _registry_for_type(option_type):
    _, address, _ = TYPES[option_type]
    return UNORDERED[address]


def parse(option_type, name):
    """Name -> value for one named-enum OptionType; None on a miss.

    Mirrors the parse helper: the linear path (element_count <= 20)
    scans the element list comparing size then memcmp; the hash path
    (element_count > 20) has identical lookup semantics.
    """
    registry = _registry_for_type(option_type)
    if len(registry) > HASH_THRESHOLD:
        return _hash_lookup(registry, name)
    return _linear_lookup(registry, name)


def _linear_lookup(registry, name):
    for entry_name, value in registry.items():
        if len(entry_name) == len(name) and entry_name == name:
            return value
    return None


def _hash_lookup(registry, name):
    # Same observable result as the hash path; the bucket walk is
    # internal to the container and cannot change the hit/miss or
    # the value returned.
    return registry.get(name)


def serialize(option_type, value):
    """Value -> name for one named-enum OptionType; None if absent.

    Mirrors the fn-60ba600 case: a linear reverse scan of the
    element list (insertion order), first match from the end wins.
    """
    registry = _registry_for_type(option_type)
    for name in reversed(list(registry)):
        if registry[name] == value:
            return name
    return None


def usable_compressions():
    """Names the 0x5d85480 consumer collects: registry values 1..254.

    kNoCompression (0) and kDisableCompressionOption (255) are
    skipped by the binary's own filter.
    """
    registry = UNORDERED["0x6507120"]
    return [name for name, value in registry.items()
            if 1 <= value <= 254]


if __name__ == "__main__":
    for option_type in sorted(TYPES):
        name, address, width = TYPES[option_type]
        registry = UNORDERED[address]
        print(f"type {option_type} {name} ({address}, "
              f"{len(registry)} entries, field {width} byte(s))")
        for entry_name, value in registry.items():
            assert serialize(option_type, value) == entry_name
            assert parse(option_type, entry_name) == value
        print("  round-trip OK; unknown ->", parse(option_type, "kNope"),
              "/", serialize(option_type, 0xFE))
    print("usable compressions:", usable_compressions())
