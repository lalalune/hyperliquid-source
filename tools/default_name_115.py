"""Python model of node #115's global default name ``"nullptr"``.

Covers RE-001-default-name-115 (node #115, artifact digest below):
the static initializer 0x61d2970 that constructs the global
``std::string`` at 0x6508980 with the literal ``"nullptr"`` and
registers its destructor with ``__cxa_atexit``, plus the exact
default-name decision at every one of the eleven consumer sites in
the binary.

The consumers' non-default paths call into the Find pipeline mapped
by #3485/#3488 and the registry translator mapped by #3440; those
callees' outcomes are harness inputs here, and their bodies are a
documented boundary of this packet (see the work-item README). What
this model pins end to end is the default-name behavior itself:
construction, the length-then-memcmp test, and the observable outcome
at each site (assign, clear, release the holder, install a fresh
object, or return 1 / 0).

Conventions: a ``Name`` is a ``(bytes, int)`` pair of (pointer
bytes, length), mirroring the (ptr, len) pairs the binary passes
around; a ``String`` is the 32-byte libstdc++ SSO object the binary
stores at 0x6508980. The mnemonics in the packet excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.
"""

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

GLOBAL_ADDR = 0x6508980
GLOBAL_TEXT = b"nullptr"
GLOBAL_LEN = 7
GLOBAL_BUFFER_ADDR = 0x6508990  # the string's own _M_local_buf

INITIALIZER = 0x61D2970
INIT_ARRAY_BASE = 0x63F36C8
INIT_ARRAY_ENTRIES = 168
INIT_ARRAY_SLOT = 141  # 0-based; the initializer is entry #142
DSO_HANDLE = 0x64EFA20  # address of __dso_handle (.data start)
DTOR_GOT = 0x64ED5D8  # GLOB_DAT: ~basic_string@GLIBCXX_3.4.21

CREATE_HOST = 0x6077820
RESOLVER_HOST = 0x607E710
TWIN_A = 0x6086B70
TWIN_B = 0x60A7420
MATCHER_WRAPPER = 0x60BF5F0
RELEASE_HOST = 0x6137290
STRING_EQUAL = 0x5E4BCF0
MAP_FIND_NAME = 0x5D66E30
KIND_VALIDATOR = 0x60BF980
KIND_VALIDATOR_JUMP_TABLE = 0x978718
KIND_COUNT = 25
ONCE_INIT_CREATE = 0x6075BC0
ONCE_INIT_RELEASE = 0x6138A10
CANONICAL_NAME = 0x6130140
FIND_ENTRY = 0x609E510
FIND_NORM = 0x609A410
MATCHER = 0x60BB9A0
STATUS_BUILDER = 0x61CF670

EMPTY_LITERAL = 0x4376FD  # "" (first byte NUL)
RESET_MESSAGE = 0x433F9F  # "Cannot reset object " (20 bytes)
RESET_MESSAGE_LEN = 20
CANONICAL_TEXT = b"rocksdb.BuiltinBloomFilter"
CANONICAL_LEN = 26
BASIC_STATISTICS_TEXT = b"BasicStatistics"
BASIC_STATISTICS_LEN = 15
CONTROL_COUNTS = 0x100000001  # the 8 bytes at .rodata 0x459b20

MAP_LINEAR_LIMIT = 20
MAP_HASH_SEED = 0xC70F6907

# The two twin consumers are instantiations of one function template:
# identical instructions except the holder-map field offset in their
# respective owners (0x630 in A, 0x90 in B). verify.py checks that
# the normalized instruction streams differ only in those two loads.
TWIN_ENTRIES = (TWIN_A, TWIN_B)
TWIN_HOLDER_OFFSETS = {TWIN_A: 0x630, TWIN_B: 0x90}


class SsoString:
    """A libstdc++ std::string in short-string form.

    Layout: _M_p (+0x00), _M_length (+0x08), _M_local_buf (+0x10).
    """

    def __init__(self, ptr=None, length=0, buf=b""):
        self.ptr = ptr
        self.length = length
        self.buf = bytes(buf)

    def bytes(self):
        if self.length == 0:
            return b""
        if self.ptr == GLOBAL_BUFFER_ADDR:
            return self.buf[:self.length]
        return self.buf[:self.length]

    def __eq__(self, other):
        return (isinstance(other, SsoString)
                and self.ptr == other.ptr
                and self.length == other.length
                and self.buf == other.buf)

    def __repr__(self):
        return "SsoString(ptr=%#x, len=%d, buf=%r)" % (
            self.ptr if self.ptr is not None else 0, self.length, self.buf)


def initialize_default_name():
    """Replicate the initializer 0x61d2970.

    Stores, in order: "null" at +0x10, _M_p = self+0x10, "lptr"
    at +0x13 (overlapping the last byte of "null" with the same
    value, so the buffer reads "nullptr"), length 7 at +0x08, and
    a NUL at +0x17. Then registers the destructor with
    __cxa_atexit(func=~basic_string from GOT 0x64ed5d8,
    arg=0x6508980, dso=0x64efa20). Returns (string, atexit_record).
    """
    s = SsoString(ptr=GLOBAL_BUFFER_ADDR, length=GLOBAL_LEN,
                  buf=b"nullptr\x00")
    atexit = {
        "func_got": DTOR_GOT,
        "func": "~basic_string@GLIBCXX_3.4.21",
        "arg": GLOBAL_ADDR,
        "dso_handle": DSO_HANDLE,
    }
    return s, atexit


def is_default_name(name_bytes, name_len):
    """The length-then-memcmp test every consumer site applies.

    Length must equal 7 first; only then are the bytes compared
    with "nullptr". A length mismatch never reaches memcmp.
    """
    if name_len != GLOBAL_LEN:
        return False
    return bytes(name_bytes)[:GLOBAL_LEN] == GLOBAL_TEXT


def string_equal(a, b):
    """Replicate 0x5e4bcf0: string equality.

    Lengths must match; a zero length is equal without memcmp;
    otherwise the bytes must compare equal.
    """
    a_bytes, a_len = a
    b_bytes, b_len = b
    if a_len != b_len:
        return False
    if a_len == 0:
        return True
    return bytes(a_bytes)[:a_len] == bytes(b_bytes)[:b_len]


def _hash_bytes(data, seed):
    """libstdc++ _Hash_bytes (MurmurHash64A) with the given seed.

    Used by map_find_name 0x5d66e30 on the hash path (> 20 entries).
    """
    m = 0xC6A4A7935BD1E995
    r = 47
    mask = 0xFFFFFFFFFFFFFFFF
    h = (seed ^ ((len(data) * m) & mask)) & mask
    nblocks = len(data) // 8
    for i in range(nblocks):
        k = int.from_bytes(data[i * 8:(i + 1) * 8], "little")
        k = (k * m) & mask
        k ^= (k >> r) & mask
        k = (k * m) & mask
        h ^= k
        h = (h * m) & mask
    tail = data[nblocks * 8:]
    if tail:
        h ^= int.from_bytes(tail.ljust(8, b"\x00"), "little")
        h = (h * m) & mask
    h ^= (h >> r) & mask
    h = (h * m) & mask
    h ^= (h >> r) & mask
    return h & mask


class MapEntry:
    """One unordered_map node: key string plus the mapped record.

    The record is the (name_ptr, name_len) pair the twins read at
    node +0x28 / +0x30.
    """

    def __init__(self, key, record):
        self.key = bytes(key)
        self.record = record
        self.stored_hash = _hash_bytes(self.key, MAP_HASH_SEED)


def map_find_name(entries, name, bucket_count):
    """Replicate 0x5d66e30: unordered_map<string, record>::find.

    ``entries`` is the node list in bucket order; ``name`` is the
    (bytes, length) key. Up to 20 entries the binary walks linearly
    (length, then memcmp); above 20 it hashes the key with seed
    0xc70f6907, takes bucket = hash % bucket_count, and walks that
    chain comparing the stored hash, then length, then memcmp.
    Returns the matched MapEntry, or None.
    """
    name_bytes, name_len = bytes(name[0]), name[1]
    if len(entries) <= MAP_LINEAR_LIMIT:
        for e in entries:
            if len(e.key) != name_len:
                continue
            if e.key[:name_len] == name_bytes[:name_len]:
                return e
        return None
    h = _hash_bytes(name_bytes[:name_len], MAP_HASH_SEED)
    bucket = h % bucket_count
    for e in entries:
        if e.stored_hash % bucket_count != bucket:
            continue
        if e.stored_hash != h:
            continue
        if len(e.key) != name_len:
            continue
        if e.key[:name_len] == name_bytes[:name_len]:
            return e
    return None


def create_host_decision(name_bytes, name_len):
    """The name gate at the top of the create host 0x6077820.

    Returns "fresh" (build a fresh StatisticsImpl and install it),
    "release" (release the holder, Status 0), or "find" (run the
    registry Find path). The pthread_once init of the TLS keys runs
    before this gate and is a precondition, not a decision.
    """
    if name_len == 0:
        return "fresh"
    if name_len == BASIC_STATISTICS_LEN and \
            bytes(name_bytes)[:name_len] == BASIC_STATISTICS_TEXT:
        return "fresh"
    if is_default_name(name_bytes, name_len):
        return "release"
    return "find"


def resolver_host_decision(delegate_present, flag_byte_set,
                           resolver_name=None):
    """The default-name branches of the resolver host 0x607e710.

    delegate_present is (*(delegate) != 0); flag_byte_set is the
    +0x04 byte of the descriptor. Returns ("assign_default", None)
    when the delegate is null, ("clear", None) when the flag is set,
    otherwise ("assign_resolver", resolver_name).
    """
    if not delegate_present:
        return ("assign_default", None)
    if flag_byte_set:
        return ("clear", None)
    return ("assign_resolver", resolver_name)


def twin_decision(validator_result, kind_ac, kind_a8,
                  holder_present, wrapper_result, lookup_record,
                  flag_ah, base_entry, candidate_name, arg5_present):
    """The twin consumers 0x6086b70 / 0x60a7420 (one function).

    ``validator_result`` is the kind validator 0x60bf980's boolean;
    ``kind_ac`` / ``kind_a8`` are the descriptor's +0xac / +0xa8
    words; ``holder_present`` is (*(arg1+0x630) != 0);
    ``wrapper_result`` is the matcher wrapper 0x60bf5f0's boolean;
    ``lookup_record`` is the (ptr, len) pair map_find_name returned
    for the candidate name, or None; ``flag_ah`` is bits 8..15 of the
    descriptor's +0xb0 word; ``base_entry`` is *(arg5 + base) when
    arg5 is present, else None; ``candidate_name`` is the arg4 string
    the tail assigns on success. Returns (code, out_name, cleared):
    code 0/1, the output name assigned (or None), and whether the
    output string was cleared by the _M_replace on the way.
    """
    if validator_result:
        return _twin_tail(kind_a8, holder_present, lookup_record,
                          flag_ah, base_entry, candidate_name,
                          arg5_present, False)
    if not (1 <= kind_ac <= 3):
        return (0, None, False)
    if not holder_present:
        return _twin_tail(kind_a8, holder_present, lookup_record,
                          flag_ah, base_entry, candidate_name,
                          arg5_present, True)
    if lookup_record is None:
        return _twin_tail(kind_a8, holder_present, lookup_record,
                          flag_ah, base_entry, candidate_name,
                          arg5_present, True)
    if not wrapper_result:
        return (0, None, False)
    return _twin_tail(kind_a8, holder_present, lookup_record,
                      flag_ah, base_entry, candidate_name,
                      arg5_present, True)


def _twin_tail(kind_a8, holder_present, lookup_record, flag_ah,
               base_entry, candidate_name, arg5_present, cleared):
    """The kind-0x15/0x16 tail shared by both twins (0x6086c1a)."""
    if not (0x15 <= kind_a8 <= 0x16):
        return (1, None, cleared)
    if not holder_present:
        return (1, None, cleared)
    if arg5_present:
        if flag_ah & 0x08:
            if base_entry is not None:
                return (1, None, cleared)
        elif not (flag_ah & 0x04):
            if not (flag_ah & 0x02):
                return (1, None, cleared)
            if base_entry is not None:
                return (1, None, cleared)
        else:
            if base_entry is not None:
                return (1, None, cleared)
    if lookup_record is None:
        return (1, None, cleared)
    rec_ptr, rec_len = lookup_record
    if rec_len == 0:
        return (1, None, cleared)
    if is_default_name(rec_ptr, rec_len):
        return (1, None, cleared)
    return (0, candidate_name, False)


def matcher_wrapper_decision(matcher_code, kind, candidate,
                             matcher_name):
    """Replicate the matcher wrapper 0x60bf5f0's verdict.

    ``matcher_code`` is the Status code the matcher 0x60bb9a0
    returned (nonzero -> False); ``kind`` is the descriptor's +0xac
    word; ``candidate`` and ``matcher_name`` are (bytes, len) pairs.
    Kind 2 compares the candidate with the default name via
    string_equal; kind 3 compares lengths with the default name,
    then memcmp, and falls back to the candidate-vs-matcher-name
    compare; any other kind compares the candidate with the
    matcher's output name directly.
    """
    if matcher_code != 0:
        return False
    if kind == 2:
        return string_equal(candidate, (GLOBAL_TEXT, GLOBAL_LEN))
    if kind == 3:
        cand_bytes, cand_len = bytes(candidate[0]), candidate[1]
        if cand_len != GLOBAL_LEN:
            return _candidate_matches_matcher(candidate, matcher_name)
        if bytes(cand_bytes)[:cand_len] == GLOBAL_TEXT:
            return True
        return _candidate_matches_matcher(candidate, matcher_name)
    return _candidate_matches_matcher(candidate, matcher_name)


def _candidate_matches_matcher(candidate, matcher_name):
    cand_bytes, cand_len = bytes(candidate[0]), candidate[1]
    out_bytes, out_len = bytes(matcher_name[0]), matcher_name[1]
    if cand_len != out_len:
        return False
    if cand_len == 0:
        return True
    return bytes(cand_bytes)[:cand_len] == bytes(out_bytes)[:out_len]


def release_host_decision(name_bytes, name_len):
    """The name gate at the top of the release host 0x6137290.

    Returns "clear" (release the holder, Status 0), "install"
    (install a fresh control block for the canonical name), or
    "find" (run the registry Find path).
    """
    if name_len == 0:
        return "clear"
    if is_default_name(name_bytes, name_len):
        return "clear"
    if name_len == CANONICAL_LEN and \
            bytes(name_bytes)[:name_len] == CANONICAL_TEXT:
        return "install"
    return "find"


def find_entry_default_check(name_len, name_bytes):
    """The default-name site in find_entry 0x609e510 (0x609e567).

    Empty name, or length 7 with bytes "nullptr", clears the name
    string and the map and returns Status 0; anything else continues
    the normal Find path (mapped in #3485).
    """
    if name_len == 0:
        return "clear"
    if is_default_name(name_bytes, name_len):
        return "clear"
    return "continue"


def find_norm_default_check(name_len, name_bytes):
    """The default-name site in find_norm 0x609a410 (0x609a45e).

    Empty name, or length 7 with bytes "nullptr", assigns the
    fallback name (harness input) into the output slot; anything
    else searches the name for '=' (mapped in #3488).
    """
    if name_len == 0:
        return "assign_fallback"
    if is_default_name(name_bytes, name_len):
        return "assign_fallback"
    return "equals_search"


def matcher_default_check(flag_b1_set, flag_04_set):
    """The default-name site in the matcher 0x60bb9a0 (0x60bbc99).

    When the resolved record's +0xb1 flag bit 0 is set, or its +0x04
    byte is clear, the matcher assigns the global default name into
    the output string; otherwise it takes the other branch (mapped
    in #3485).
    """
    if flag_b1_set or not flag_04_set:
        return "assign_default"
    return "other_branch"
