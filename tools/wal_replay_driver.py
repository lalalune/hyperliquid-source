"""Model of node #94 WAL replay driver 0x520c120 (RE-001).

The driver dispatches on an unsigned file type, looks a log number up
in a mutex-guarded replay cache, builds the log filename for a cache
miss, runs one replay step, and either caches the result, propagates
the replay status, or runs an error callback chain. The model pins
the observable behavior from research/work-items/RE-001-wal-replay-
driver-94/; callee internals beyond their pinned contracts (the replay
step, the filename builders, the chain method) are collaborator hooks
so tests can drive every path end to end.

Status layout (6 bytes plus a pointer at +8) is carried as code
(byte 0), rest (bytes 1..5), pointer, and -- for the unknown-type
status only -- the detail message. The driver itself inspects only
byte 0; propagation copies the saved six bytes unchanged.
"""

LOG_FILE = "db/wal_manager.cc"
LOG_FORMAT = "[%s:381] [WalManger] Unknown file type %s"
UNKNOWN_PREFIX = "File Type Not Known "
UNKNOWN_CODE = 3
UNKNOWN_SUBCODE = 0

# Magnitude thresholds for the decimal digit count, exactly as the
# entry dispatch branches on them (9/99/999/9999/99999/999999/
# 9999999/99999999/999999999, else 10 digits).
_DIGIT_THRESHOLDS = (9, 99, 999, 9999, 99999, 999999, 9999999,
                     99999999, 999999999)


def decimal_digit_count(magnitude):
    """Digit count for a nonnegative magnitude, per the binary."""
    for i, limit in enumerate(_DIGIT_THRESHOLDS, start=1):
        if magnitude <= limit:
            return i
    return 10


def format_decimal(value_u32):
    """Format a u32 file-type value as the binary's SIGNED decimal.

    Sign = bit 31; magnitude = abs of the signed reading (INT_MIN
    keeps magnitude 2147483648, whose digits are the signed value's).
    Digits are produced least-significant-pair first against the
    "00".."99" pair table in the binary; this arithmetic form renders
    the same strings.
    """
    signed = value_u32 - (1 << 32) if value_u32 >= (1 << 31) else value_u32
    if signed < 0:
        return "-" + str(-signed)
    return str(signed)


def unknown_type_log_line(file_type):
    """Rendered unknown-type log line (verbatim WalManger spelling)."""
    return LOG_FORMAT % (LOG_FILE, format_decimal(file_type))


def log_file_name(log_number):
    """The shared name component: %06llu.%s with ("log")."""
    return "%06d.log" % log_number


def filename_for(file_type, directory, runtime_component, log_number):
    """Filename for a file type (0 = subdir path, 1 = direct path)."""
    name = log_file_name(log_number)
    if file_type == 0:
        return "%s/%s/%s" % (directory, runtime_component, name)
    if file_type == 1:
        return "%s/%s" % (directory, name)
    raise ValueError("unknown file type: %r" % (file_type,))


class Status:
    """A driver status: 6 bytes (code + rest) plus a pointer field."""

    def __init__(self, code=0, rest=(0, 0, 0, 0, 0), pointer=None,
                 message=None):
        self.code = code
        self.rest = tuple(rest)
        self.pointer = pointer
        self.message = message

    @classmethod
    def zero(cls):
        return cls(0, (0, 0, 0, 0, 0), None)

    @classmethod
    def unknown(cls, file_type):
        return cls(UNKNOWN_CODE, (UNKNOWN_SUBCODE, 0, 0, 0, 0), None,
                   UNKNOWN_PREFIX + format_decimal(file_type))

    def with_code(self, code):
        return Status(code, self.rest, self.pointer, self.message)

    def __eq__(self, other):
        return (isinstance(other, Status)
                and (self.code, self.rest, self.pointer, self.message)
                == (other.code, other.rest, other.pointer, other.message))

    def __repr__(self):
        return "Status(code=%r, rest=%r, pointer=%r, message=%r)" % (
            self.code, self.rest, self.pointer, self.message)


class _Node:
    __slots__ = ("next", "key", "value")

    def __init__(self, key, value, nxt=None):
        self.next = nxt
        self.key = key
        self.value = value


class _Sentinel:
    """The table head marker: bucket entries for head-first buckets."""

    __slots__ = ("next",)

    def __init__(self):
        self.next = None


class CacheTable:
    """The replay cache: buckets, count, head, element count, policy.

    Bucket entries point at a before-node (or the head sentinel for
    head-first buckets); an unwritten bucket entry is None. The
    growth policy is a hook: it receives (bucket_count, element_count)
    and returns (need_rehash, new_count). The default models the
    standard load-factor-1.0 shape (rehash when the next insert would
    exceed one element per bucket, doubling the count); the binary
    only pins the _M_need_rehash call contract, not the float, so
    tests may substitute the policy.
    """

    def __init__(self, bucket_count=1, growth_policy=None):
        self.bucket_count = bucket_count
        self.buckets = [None] * bucket_count
        self.head = _Sentinel()
        self.element_count = 0
        self.growth_policy = growth_policy or self._default_policy

    @staticmethod
    def _default_policy(bucket_count, element_count):
        need = (element_count + 1) > bucket_count
        return need, max(1, bucket_count * 2)

    def _bucket(self, key):
        return key % self.bucket_count

    def lookup(self, key):
        """Return (found, value); segment walk, linear when empty."""
        if self.element_count == 0:
            node = self.head.next
            while node is not None:
                if node.key == key:
                    return True, node.value
                node = node.next
            return False, None
        bucket = self._bucket(key)
        before = self.buckets[bucket]
        if before is None:
            return False, None
        node = before.next
        while node is not None and self._bucket(node.key) == bucket:
            if node.key == key:
                return True, node.value
            node = node.next
        return False, None

    def insert(self, key, value):
        """Insert if absent; return True when a node was added."""
        need, new_count = self.growth_policy(self.bucket_count,
                                             self.element_count)
        if need:
            self._rehash(new_count)
        bucket = self._bucket(key)
        before = self.buckets[bucket]
        if before is None:
            # Empty bucket: prepend to head, repoint the old head's
            # bucket entry (if any), entry becomes the sentinel.
            old_head = self.head.next
            node = _Node(key, value, old_head)
            self.head.next = node
            if old_head is not None:
                self.buckets[self._bucket(old_head.key)] = node
            self.buckets[bucket] = self.head
        else:
            # Duplicate check only: walk the bucket segment from the
            # entry's successor. Insertion always goes right after
            # the ENTRY node (the recorded before-node), ahead of
            # the whole segment, so segments stay contiguous.
            node = before.next
            while node is not None and self._bucket(node.key) == bucket:
                if node.key == key:
                    return False
                node = node.next
            fresh = _Node(key, value, before.next)
            before.next = fresh
        self.element_count += 1
        return True

    def _rehash(self, new_count):
        # Collect the chain in order, then rebuild bucket entries so
        # each entry points at the before-node of its bucket's first
        # node (or the sentinel when that node is the head).
        nodes = []
        node = self.head.next
        while node is not None:
            nodes.append(node)
            node = node.next
        self.bucket_count = new_count
        self.buckets = [None] * new_count
        self.head = _Sentinel()
        for i, node in enumerate(nodes):
            node.next = nodes[i + 1] if i + 1 < len(nodes) else None
        self.head.next = nodes[0] if nodes else None
        for i, node in enumerate(nodes):
            bucket = self._bucket(node.key)
            if self.buckets[bucket] is None:
                self.buckets[bucket] = nodes[i - 1] if i > 0 else self.head


class ReplayDriver:
    """The driver with injectable collaborators.

    replay_step(filename, log_number) returns (Status, slot_value).
    chain_callback(status, filename) returns the scratch status byte 0
    after the callback runs. Events record the observable call order.
    """

    def __init__(self, directory, runtime_component, table,
                 replay_step, chain_callback):
        self.directory = directory
        self.runtime_component = runtime_component
        self.table = table
        self.replay_step = replay_step
        self.chain_callback = chain_callback
        self.events = []

    def _post_replay_type0(self, saved, slot, filename, log_number):
        if saved.code == 0:
            if slot != 0:
                self.events.append("lock-insert")
                self.table.insert(log_number, slot)
                self.events.append("unlock-insert")
            return saved.with_code(0), slot
        new_byte0 = self.chain_callback(saved, filename)
        self.events.append("chain:%d" % new_byte0)
        if new_byte0 == 1:
            return Status.zero(), slot
        return saved, slot

    def run(self, file_type, log_number):
        """Run one driver call; return (Status, out_slot_value)."""
        slot = 0
        if file_type > 1:
            self.events.append("log:" + unknown_type_log_line(file_type))
            return Status.unknown(file_type), slot
        self.events.append("lock-lookup")
        found, value = self.table.lookup(log_number)
        if found:
            slot = value
            self.events.append("unlock-lookup")
            return Status.zero(), slot
        self.events.append("unlock-lookup")
        if file_type == 0:
            filename = filename_for(0, self.directory,
                                    self.runtime_component, log_number)
            self.events.append("filename0:" + filename)
            saved, slot = self.replay_step(filename, log_number)
            self.events.append("replay0")
            return self._post_replay_type0(saved, slot, filename,
                                           log_number)
        filename = filename_for(1, self.directory,
                                self.runtime_component, log_number)
        self.events.append("filename1:" + filename)
        saved, slot = self.replay_step(filename, log_number)
        self.events.append("replay1")
        if saved.code == 0:
            return saved, slot
        new_byte0 = self.chain_callback(saved, filename)
        self.events.append("chain:%d" % new_byte0)
        if new_byte0 == 0:
            return saved, slot
        # Retry as type 0, with the full type-0 post-replay sequence.
        filename0 = filename_for(0, self.directory,
                                 self.runtime_component, log_number)
        self.events.append("filename0-retry:" + filename0)
        saved2, slot = self.replay_step(filename0, log_number)
        self.events.append("replay0-retry")
        return self._post_replay_type0(saved2, slot, filename0,
                                       log_number)
