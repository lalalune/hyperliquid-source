"""Python model of node #115's builtin FilterPolicy registrations (RE-001).

Bound to work/hl-node-115.bin
(sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Models the builtin registrar 0x6137fe0, which registers nine FilterPolicy
factories under the single map key 'FilterPolicy' (one inlined, eight
through the per-factory registrar 0x6137810), and the nine creator
invokers those factories carry. Evidence lives in
research/work-items/RE-001-filter-policy-registrations-115/.

Registration flow (per factory):

    registrar(library)                       [0x6137fe0]
      -> entry_builder(entry, name_part)     [0x6134be0, cited]
      -> vec_append(entry.names, full_name)  [0x61350b0, cited]
      -> per_factory_registrar(library, entry, factory)  [0x6137810]
           -> register(library+0x28, "FilterPolicy")     [0x5fd1da0]
           -> append the new FactoryEntry record to the map node

Creator contract (from the dispatch, #4458): the invoker takes
(record, name, &slot, &string), stores the new raw object at the slot,
releases the previous object through its vtable slot 1 when non-null,
and returns the new object. Eight of the nine split the requested name
on ':' (0x61d2380) and parse the second part as a double (0x61d1e30);
the builtin creator 0x612de10 does no parsing at all.

Matching: the model's find_factory implements the documented reading of
the PatternEntry -- the requested name's first ':'-segment must equal
the entry name, and among same-name entries the one whose option
elements match the trailing segments wins (most specific). The exact
matching semantics of PatternEntry Matches (0x61f8670) are cited, not
pinned, so the matcher is a model of the recorded pattern, not a
binary claim.

The ':true' ribbon factory is the table's exception: it builds a
0x40-byte BloomFilterPolicy (vtable 0x64d4f20), not a RibbonFilterPolicy.
The plain and ':' ribbon factories build 0x48-byte RibbonFilterPolicy
objects (vtable 0x64d52e0). Whether upstream intends that is an open
unknown; the invoker bodies are pinned, the intent is not.
"""

# The pinned routines.
REGISTRAR = 0x6137FE0          # builtin FilterPolicy registrar
PER_FACTORY_REGISTRAR = 0x6137810  # per-factory registrar
REG_INIT = 0x6138A10           # pthread_once init calling REGISTRAR
REGISTER_HELPER = 0x5FD1DA0    # registry register helper
ENTRY_BUILDER = 0x6134BE0      # PatternEntry builder (cited)
VEC_APPEND = 0x61350B0         # names-vector append (cited)
STR_CTOR = 0x612F730           # std::string ctor from a C string
STR_COPY = 0x612DF20           # string copy helper
SPLIT = 0x61D2380              # ':'-split helper (cited)
PARSE_DOUBLE = 0x61D1E30       # double parse helper (cited)
PARSE_INT = 0x61D1B90          # int parse helper (cited)
BASE_CTOR = 0x612FC30          # shared filter-policy base ctor (cited)
BLOOM_CTOR = 0x6130160         # BloomFilterPolicy ctor wrapper (cited)
BLOOM_HELPER = 0x6131DF0       # Bloom factory helper, ignores its int arg
RIBBON_HELPER = 0x6131EC0      # Ribbon factory helper (cited)
RIBBON_CTOR = 0x6131E40        # RibbonFilterPolicy ctor (cited)

# Map key every registration uses (literal 0x44d20e).
MAP_KEY = "FilterPolicy"

# The nine managers: one 0x2d-byte template at 0x612d2a0 + k*0x30.
# Op 0 stores the lambda typeinfo into *rdi, op 1 stores rsi into *rdi,
# op 2 (clone) and op 3 (destroy) are no-ops (stateless lambdas).
MANAGER_OP_TYPEINFO = 0
MANAGER_OP_FUNCTOR_PTR = 1
MANAGER_OP_CLONE = 2
MANAGER_OP_DESTROY = 3


class FactoryEntry:
    """One registered FilterPolicy factory (a row of the table)."""

    def __init__(self, index, entry_name, pattern_parts, option_elements,
                 manager, invoker, call_site, policy_class, size,
                 vtable, typeinfo, ctor):
        self.index = index
        self.entry_name = entry_name
        self.pattern_parts = list(pattern_parts)
        # option_elements: list of (text, tag) pairs, e.g. (":false", 2).
        self.option_elements = list(option_elements)
        self.manager = manager
        self.invoker = invoker
        self.call_site = call_site
        self.policy_class = policy_class
        self.size = size
        self.vtable = vtable
        self.typeinfo = typeinfo
        self.ctor = ctor

    def __repr__(self):
        return (f"FactoryEntry({self.index}, {self.entry_name!r}, "
                f"invoker={self.invoker:#x}, builds={self.policy_class})")


# The registration table, in registration order. Manager/invoker
# addresses, sizes, vtables and typeinfo names are pinned in
# research/work-items/RE-001-filter-policy-registrations-115/.
REGISTRATIONS = [
    FactoryEntry(
        1, "rocksdb.BuiltinBloomFilter", ["rocksdb.BuiltinBloomFilter"],
        [], 0x612D2A0, 0x612DE10, "inlined in 0x6137fe0; register 0x613818f",
        "rocksdb::ReadOnlyBuiltinFilterPolicy", 0x20, 0x64D4AF0,
        "N7rocksdb27ReadOnlyBuiltinFilterPolicyE", None),
    FactoryEntry(
        2, "bloomfilter", ["bloomfilter", "rocksdb.BloomFilter"],
        [], 0x612D2D0, 0x6134130, "0x613825f -> 0x6137810",
        "rocksdb::BloomFilterPolicy", 0x40, 0x64D4F20,
        "N7rocksdb17BloomFilterPolicyE", "0x6130160"),
    FactoryEntry(
        3, "bloomfilter", ["bloomfilter", "rocksdb.BloomFilter"],
        [(":false", 2)], 0x612D300, 0x61338A0, "0x6138356 -> 0x6137810",
        "rocksdb::BloomFilterPolicy", 0x40, 0x64D4F20,
        "N7rocksdb17BloomFilterPolicyE", "0x6130160"),
    FactoryEntry(
        4, "ribbonfilter", ["ribbonfilter", "rocksdb.RibbonFilter"],
        [(":true", 2)], 0x612D330, 0x6134010, "0x6138450 -> 0x6137810",
        # The asymmetry: the ':true' ribbon factory builds a Bloom policy.
        "rocksdb::BloomFilterPolicy", 0x40, 0x64D4F20,
        "N7rocksdb17BloomFilterPolicyE", "0x6131df0 -> 0x6130160"),
    FactoryEntry(
        5, "ribbonfilter", ["ribbonfilter", "rocksdb.RibbonFilter"],
        [], 0x612D360, 0x6133EF0, "0x61384e3 -> 0x6137810",
        "rocksdb::RibbonFilterPolicy", 0x48, 0x64D52E0,
        "N7rocksdb18RibbonFilterPolicyE", "0x6131ec0 -> 0x6131e40"),
    FactoryEntry(
        6, "ribbonfilter", ["ribbonfilter", "rocksdb.RibbonFilter"],
        [(":", 3)], 0x612D390, 0x6133DC0, "0x61385eb -> 0x6137810",
        "rocksdb::RibbonFilterPolicy", 0x48, 0x64D52E0,
        "N7rocksdb18RibbonFilterPolicyE", "0x6131ec0 -> 0x6131e40"),
    FactoryEntry(
        7, "rocksdb.internal.LegacyBloomFilter",
        ["rocksdb.internal.LegacyBloomFilter"],
        [], 0x612D3C0, 0x61339E0, "0x6138662 -> 0x6137810",
        "rocksdb::test::LegacyBloomFilterPolicy", 0x40, 0x64D4FE0,
        "N7rocksdb4test23LegacyBloomFilterPolicyE", "0x612fc30"),
    FactoryEntry(
        8, "rocksdb.internal.FastLocalBloomFilter",
        ["rocksdb.internal.FastLocalBloomFilter"],
        [], 0x612D3F0, 0x6133B30, "0x61386c9 -> 0x6137810",
        "rocksdb::test::FastLocalBloomFilterPolicy", 0x40, 0x64D50A0,
        "N7rocksdb4test26FastLocalBloomFilterPolicyE", "0x612fc30"),
    FactoryEntry(
        9, "rocksdb.internal.Standard128RibbonFilter",
        ["rocksdb.internal.Standard128RibbonFilter"],
        [], 0x612D420, 0x6133C80, "0x6138730 -> 0x6137810",
        "rocksdb::test::Standard128RibbonFilterPolicy", 0x40, 0x64D5160,
        "N7rocksdb4test29Standard128RibbonFilterPolicyE", "0x612fc30"),
]


class Policy:
    """A policy object built by a creator invoker."""

    def __init__(self, policy_class, size, vtable, bits=None, int_param=None):
        self.policy_class = policy_class
        self.size = size
        self.vtable = vtable
        self.bits = bits            # the parsed double (second ':' part)
        self.int_param = int_param  # the parsed int (third ':' part, ribbon ':')

    def __repr__(self):
        return (f"Policy({self.policy_class}, size={self.size:#x}, "
                f"vtable={self.vtable:#x}, bits={self.bits}, "
                f"int_param={self.int_param})")


def split_name(name):
    """The observed ':'-split contract of 0x61d2380 (cited, not pinned)."""
    return name.split(":")


def parse_double(text):
    """The observed double-parse contract of 0x61d1e30 (cited, not pinned)."""
    return float(text)


def parse_int(text):
    """The observed int-parse contract of 0x61d1b90 (cited, not pinned)."""
    return int(text)


def _option_matches(entry, parts):
    """Do the entry's option elements match the requested name's tail?

    Tag 2 elements (':false' / ':true') match when the requested name
    ends with that literal; the tag-3 ':' element matches when the name
    carries a third ':'-separated part. Entries without option elements
    match any suffix.
    """
    if not entry.option_elements:
        return True
    for text, tag in entry.option_elements:
        if tag == 2:
            if not ":".join(parts).endswith(text):
                return False
        elif tag == 3:
            if len(parts) < 3:
                return False
        else:
            return False
    return True


def find_factory(requested_name):
    """Select the factory for a requested name, or None.

    Model of the PatternEntry match: the first ':'-segment must equal
    the entry name; among same-name entries the one with the most
    matching option elements wins. The exact Matches (0x61f8670)
    semantics are cited, not pinned.
    """
    parts = split_name(requested_name)
    best = None
    for entry in REGISTRATIONS:
        if parts[0] != entry.entry_name:
            continue
        if not _option_matches(entry, parts):
            continue
        if best is None or len(entry.option_elements) > len(best.option_elements):
            best = entry
    return best


def create(requested_name, slot=None):
    """Run the matched creator for a requested name.

    Returns the new Policy, stored into the slot dict (the out slot) when
    given; a previous object in the slot is released (modelled as
    dropping the reference, as the invokers do through vtable slot 1).
    Raises LookupError when no factory matches.
    """
    entry = find_factory(requested_name)
    if entry is None:
        raise LookupError(f"no FilterPolicy factory for {requested_name!r}")
    parts = split_name(requested_name)
    # The builtin creator 0x612de10 does no parsing at all: it ignores
    # the requested name, so bits stays None even for a suffixed name.
    bits = None
    if entry.invoker != 0x612DE10 and len(parts) > 1 and parts[1]:
        bits = parse_double(parts[1])
    int_param = None
    if entry.invoker == 0x6133DC0 and len(parts) > 2 and parts[2]:
        int_param = parse_int(parts[2])
    if entry.invoker == 0x6133EF0:
        int_param = 0
    policy = Policy(entry.policy_class, entry.size, entry.vtable,
                    bits=bits, int_param=int_param)
    if slot is not None:
        slot["policy"] = policy
    return policy


def manager_op(manager, op, functor=None):
    """The lambda manager template (0x612d2a0 shape).

    Op 0 returns the lambda typeinfo, op 1 returns the functor pointer,
    op 2 (clone) and op 3 (destroy) are no-ops returning None.
    """
    if op == MANAGER_OP_TYPEINFO:
        return "RegisterBuiltinFilterPolicies lambda"
    if op == MANAGER_OP_FUNCTOR_PTR:
        return functor
    if op in (MANAGER_OP_CLONE, MANAGER_OP_DESTROY):
        return None
    raise ValueError(f"unknown manager op {op}")
