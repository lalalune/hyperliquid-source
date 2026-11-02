"""Model of node #94 0x5157d30: the BlockCache report builder.

The window (0x5157d30..0x5158ebe, FDE 0x00634b10) takes a snapshot,
a render target and a clock holder, and rebuilds the target's
keyed report map from the snapshot, in place:

  1. clear: call the teardown 0x514bf60 on [target+0x10] (it deletes
     every map node: recurse on the +0x18 link, dispose the +0x40
     value string and the +0x20 key string when they are heap
     strings, delete the 0x60-byte node, then iterate the +0x10
     link), then reset the header: [target+0x10] = 0,
     [target+0x18] = [target+0x20] = target+0x08, [target+0x28] = 0;
  2. header entries, each find-or-insert by key (0x5153a70, which
     returns the node's value string at +0x40) followed by an
     assign into that string:
       "id" -> snapshot+0x20 identity string, copy-assigned;
       "capacity" -> decimal(snapshot+0x00) via the itoa 0x4faf340;
       "secs_for_last_collection" -> "%f" % (window_seconds),
         where window_seconds = unsigned_to_double(accessor) /
         1,000,000.0 and the accessor 0x514df50 returns 0 when
         [snapshot+0x128] >= [snapshot+0x130] (unsigned), else
         [snapshot+0x130] - [snapshot+0x128];
       "secs_since_last_collection" -> decimal(secs_since), where
         secs_since = (clock - [snapshot+0x130]) mod 2**64 divided
         by 1,000,000 with the 0x431bde82d7b634db magic (shift 82
         after the 128-bit multiply), and clock is the [holder]
         +0x98 dispatch result;
  3. per-entry loop, i = 0..13, each phase formatting one string,
     building one key, find-or-inserting it, and assigning the
     formatted string into the node's +0x40 value string:
       "count." + name[i]   -> itoa(snapshot+0xb0 + i*8);
       "bytes." + name[i]   -> itoa(snapshot+0x40 + i*8);
       "percent." + name[i] -> "%f" % (value * 100.0 / denominator),
         where value = snapshot+0x40 + i*8 and denominator =
         snapshot+0x00, both converted from uint64 with the
         unsigned idiom below (a zero denominator gives inf, and
         0/0 gives nan, as with divsd);
  4. canary check, then return (void).

The itoa is the digit-pair algorithm: the digit count comes from
the threshold ladder (<= 9, <= 99, <= 999, <= 9999, then 4-digit
chunks), the string is constructed at that length, and digits are
written two at a time from the end using the "00".."99" pair table
that the window copies onto the stack (verified byte-for-byte
against the binary's .rodata vectors); a leftover leading digit
gets '0' + digit. It treats its input as unsigned throughout.

The find-or-insert walk scans the +0x18 links from [target+0x10]
while the visited node's key is smaller than the searched key
under the string comparison (memcmp over the common prefix, then
the length difference saturated to int32: a difference >= 2**31
stops the walk, a difference <= -2**31 - 1 continues it); it
stops at the first node whose key is >= the searched key, then
re-checks that node for equality (same comparison, both
directions); on equality it reuses the node, otherwise it calls
the insert callee 0x5153650 with (target, stopped node, key) and
uses the new node. The map is therefore kept in ascending key
order; for the short keys here the comparison is exactly Python
bytes ordering.

The node+0x40 assign has two arms with the same observable
content: when the formatted temp string is SSO (its pointer
equals its own buffer) the bytes are copied (memcpy, with len 0
and len 1 special-cased) and NUL-terminated into the node's
existing buffer; when it is a heap string, the node's old heap
buffer (if any) is freed and the temp's pointer is stolen. The
model records the contents only; allocation is not observable
through the map. Each phase's epilogue likewise disposes the
name string and the temp string (sized delete only for heap
strings); those disposals leave no observable state.

The entry names come from 0x515f8d0(i): record i (32 bytes:
pointer, length) at the base loaded from the GOT slot 0x5777978.
That slot is zero in the file (resolved at load), so the names
are model parameters here, not file contents; the record shape
matches the 0x578c2e0 table the 0x514f770 formatter reads.

Exception cleanup (0x5157c0c..0x5157d2a, FDE 0x00634b64) sits
immediately before the window, with 6 int3 padding bytes to the
window start. The window's tail holds 9 landing stubs (endbr64;
mov exception object to rbx; jmp into the cleanup), one per
cleanup entry; which stub serves which call site is not claimed
(LSDA mapping). The cleanup disposes the stack strings; it is
cited, not modelled.

Callees cited only, not re-claimed: the teardown 0x514bf60, the
find-or-insert 0x5153a70, the insert 0x5153650, the itoa
0x4faf340, the double formatter 0x514c050 (format "%f" at
0x1df3ed), the accessor 0x514df50, the static-key helpers
0x515f8f0 ("id"), 0x515f990 ("capacity"), 0x515fa60
("secs_for_last_collection"), 0x515fb90
("secs_since_last_collection"), and the per-phase key helpers
0x515fca0 ("count." + name), 0x515fdf0 ("bytes." + name),
0x515ff40 ("percent." + name). The double formatter's "%f" is
read from the binary's .rodata, not assumed; C "%f" and Python
"%f" agree on finite values, inf and nan spellings.

Snapshot+0x120/+0x124 (collections/last_copies in the 0x514f770
formatter's header) are not consumed by this builder; the
0x514f770 formatter scales snapshot+0x00 through KB/MB/GB/TB
while this builder's "capacity" entry is its plain decimal --
an observed difference, not explained.
"""

MASK64 = (1 << 64) - 1
SECS_MAGIC = 0x431BDE82D7B634DB
PAIR_TABLE = "".join("%02d" % i for i in range(100))

HEADER_KEYS = ("id", "capacity", "secs_for_last_collection",
               "secs_since_last_collection")
ENTRY_COUNT = 14


def unsigned_to_double(value):
    """(double)(uint64_t)value, as the binary's js arms compute it.

    The negative arms (0x5158d53, 0x5158af0, 0x5158b10) use the
    (x >> 1) | (x & 1), doubled idiom. For every value that takes
    those arms (high bit set, so >= 2**63) the +/-1 error of the
    idiom is below double spacing, so the correctly rounded
    result equals float(value); values with the high bit clear
    take the plain cvtsi2sd path, which is also float(value).
    """
    return float(value & MASK64)


def magic_div_1e6(value):
    """Floor division by 1,000,000 via the binary's magic.

    (value * 0x431bde82d7b634db) >> 82, i.e. the high word of the
    128-bit product shifted right by 18. Checked against //
    1_000_000 on edges and 20,000 random 64-bit values: exact.
    """
    return ((value & MASK64) * SECS_MAGIC) >> 82


def digit_count(value):
    """Decimal digit count, following the window's ladder."""
    value &= MASK64
    if value <= 9:
        return 1
    if value <= 99:
        return 2
    if value <= 999:
        return 3
    if value <= 9999:
        return 4
    return 4 + digit_count(value // 10000)


def itoa(value):
    """Decimal string for an unsigned 64-bit value, pair-filled."""
    value &= MASK64
    chars = ["\0"] * digit_count(value)
    i = len(chars)
    rest = value
    while rest >= 100:
        rest, rem = divmod(rest, 100)
        chars[i - 2:i] = PAIR_TABLE[2 * rem:2 * rem + 2]
        i -= 2
    if i == 2:
        chars[0:2] = PAIR_TABLE[2 * rest:2 * rest + 2]
    elif i == 1:
        chars[0] = chr(ord("0") + rest)
    return "".join(chars)


def format_f(value):
    """C "%f" formatting of a double (6 fractional digits)."""
    return "%f" % value


def ratio_percent(value, denominator):
    """value * 100.0 / denominator with divsd semantics.

    Python raises on 0.0/0.0; divsd yields nan there, and inf for
    a nonzero numerator over a zero denominator. Values here are
    unsigned, so the infinities are positive.
    """
    numerator = unsigned_to_double(value) * 100.0
    denom = unsigned_to_double(denominator)
    if denom == 0.0:
        return float("nan") if numerator == 0.0 else float("inf")
    return numerator / denom


def compare_keys(key, node_key):
    """Saturating string comparison, as the walk computes it.

    Returns -1/0/1 for key vs node_key: memcmp sign over the
    common prefix, else the length difference saturated at the
    walk's arms (node longer by >= 2**31 counts as node greater,
    node shorter by > 2**31 counts as node smaller). For short
    keys this is exactly bytes ordering.
    """
    key = key.encode() if isinstance(key, str) else key
    node_key = node_key.encode() if isinstance(node_key, str) else node_key
    common = min(len(key), len(node_key))
    if key[:common] != node_key[:common]:
        return -1 if key[:common] < node_key[:common] else 1
    diff = len(node_key) - len(key)
    if diff >= (1 << 31):
        return -1
    if diff <= -(1 << 31) - 1:
        return 1
    if diff == 0:
        return 0
    return -1 if diff > 0 else 1


class ReportMap:
    """The target's keyed map, kept in ascending key order."""

    def __init__(self):
        self._keys = []
        self._values = {}

    def find_or_insert(self, key):
        """Return (key, is_new) under the walk's ordering."""
        if key in self._values:
            return key, False
        pos = 0
        while pos < len(self._keys) and \
                compare_keys(key, self._keys[pos]) > 0:
            pos += 1
        self._keys.insert(pos, key)
        self._values[key] = ""
        return key, True

    def assign(self, key, value):
        self._values[key] = value

    def items(self):
        return [(k, self._values[k]) for k in self._keys]

    def as_dict(self):
        return dict(self.items())


class Snapshot:
    """The 0x138-byte snapshot fields this builder consumes."""

    def __init__(self, denominator=0, identity="", values=None,
                 counters=None, last_secs_raw=0, commit=0):
        self.denominator = denominator & MASK64
        self.identity = identity
        self.values = [(v & MASK64) for v in
                       (values or [0] * ENTRY_COUNT)]
        self.counters = [(v & MASK64) for v in
                         (counters or [0] * ENTRY_COUNT)]
        self.last_secs_raw = last_secs_raw & MASK64
        self.commit = commit & MASK64
        if len(self.values) != ENTRY_COUNT or \
                len(self.counters) != ENTRY_COUNT:
            raise ValueError("need exactly 14 values and 14 counters")


def accessor_window(snapshot):
    """0x514df50: 0 if last_secs_raw >= commit (unsigned), else diff."""
    if snapshot.last_secs_raw >= snapshot.commit:
        return 0
    return (snapshot.commit - snapshot.last_secs_raw) & MASK64


def build_report(snapshot, names, clock_value):
    """Rebuild the target map from the snapshot; return ReportMap.

    ``names`` is the 14-entry name table (model parameters);
    ``clock_value`` is the [holder] +0x98 dispatch result.
    """
    if len(names) != ENTRY_COUNT:
        raise ValueError("need exactly 14 entry names")
    target = ReportMap()
    # Header entries (the map was cleared first, so all are new).
    target.find_or_insert("id")
    target.assign("id", snapshot.identity)
    target.find_or_insert("capacity")
    target.assign("capacity", itoa(snapshot.denominator))
    window = accessor_window(snapshot)
    target.find_or_insert("secs_for_last_collection")
    target.assign("secs_for_last_collection",
                  format_f(unsigned_to_double(window) / 1000000.0))
    diff = (clock_value - snapshot.commit) & MASK64
    target.find_or_insert("secs_since_last_collection")
    target.assign("secs_since_last_collection",
                  itoa(magic_div_1e6(diff)))
    # Per-entry loop.
    for i in range(ENTRY_COUNT):
        key = "count." + names[i]
        target.find_or_insert(key)
        target.assign(key, itoa(snapshot.counters[i]))
        key = "bytes." + names[i]
        target.find_or_insert(key)
        target.assign(key, itoa(snapshot.values[i]))
        ratio = ratio_percent(snapshot.values[i],
                              snapshot.denominator)
        key = "percent." + names[i]
        target.find_or_insert(key)
        target.assign(key, format_f(ratio))
    return target
