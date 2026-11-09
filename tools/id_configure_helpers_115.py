"""Model of the node #115 id-configure helper 0x609a410, the slot-9 entry
0x6097150/0x6097110, and their shared vtable slot 9 (0x609d0e0).

Grounding: research/work-items/RE-001-id-configure-helpers-115/ (node #115,
artifact sha256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).
The map parser 0x60c1190 is modelled only by its outcome (parsed entries or
failure); its own three kInvalidArgument outcomes were pinned in #4320.
"""

BSS_STRING_ADDR = 0x6508980  # .bss std::string; runtime content not pinned
DELIMITER = "; "
NULL_OBJECT_MESSAGE = "Cannot configure null object "
NULL_OBJECT_CODE = 4  # kInvalidArgument
SLOT9_ADDR = 0x609D0E0
SLOT9_VTABLE_OFFSET = 0x48  # slot 9
FIND_LINEAR_MAX_ELEMENTS = 20  # 0x609a1b0: linear scan at/below this count
FIND_HASH_SEED = 0xC70F6907
MAP_NODE_SIZE = 0x50
MAP_SIZE = 0x38  # 56 bytes: unordered_map<string, string>

# unordered_map node layout (libstdc++ _Hash_node<string, string> pair).
NODE_NEXT = 0x00
NODE_KEY_PTR = 0x08
NODE_KEY_SIZE = 0x10
NODE_KEY_SSO = 0x18
NODE_VALUE_PTR = 0x28
NODE_VALUE_SIZE = 0x30
NODE_VALUE_SSO = 0x38
NODE_HASH = 0x48

# unordered_map layout (libstdc++ _Hashtable).
MAP_BUCKETS = 0x00
MAP_BUCKET_COUNT = 0x08
MAP_BEFORE_BEGIN = 0x10
MAP_ELEMENT_COUNT = 0x18
MAP_MAX_LOAD_FACTOR = 0x20
MAP_NEXT_RESIZE = 0x28
MAP_SINGLE_BUCKET = 0x30


class Status:
    """Minimal RocksDB Status: code 0 is kOk."""

    def __init__(self, code=0, message=""):
        self.code = code
        self.message = message

    def is_ok(self):
        return self.code == 0


def resolve_id_name(input_str, id_str, bss_str, parse_ok, parsed):
    """Model of 0x609a410.

    Args:
        input_str: the value string being configured.
        id_str: the target's GetId() output.
        bss_str: the runtime .bss string at 0x6508980 (content unpinned;
            pass the observed value when testing).
        parse_ok: whether the map parser 0x60c1190 succeeded on input_str.
        parsed: the map entries the parser produced (dict), or None when
            parsing was not attempted / failed.

    Returns (out_name, surviving_entries_or_None, status).
    surviving_entries is the map content the caller still sees afterwards:
    None means the map was cleared, a dict means it survives.
    """
    status = Status(0)
    if input_str == "":
        return id_str, parsed, status
    if input_str == bss_str:
        return id_str, parsed, status
    if "=" not in input_str:
        return input_str, parsed, status
    if not parse_ok:
        # Parse failure is discarded: name falls back to the input, the
        # map is cleared, and out is reset to kOk.
        return input_str, None, status
    entries = dict(parsed)
    if "id" in entries:
        out_name = entries.pop("id")
        if out_name == bss_str:
            out_name = ""
        return out_name, entries, status
    if id_str != "":
        return id_str, entries, status
    return input_str, None, status


def slot9_path(map_empty, config_byte0, config_byte3, apply_status_ok, s0_nonempty):
    """Model of the slot-9 (0x609d0e0) branch structure.

    Returns the ordered list of actions taken: a subset of
    'return_kok', 'call_slot5', 'delimiter_prestep', 'call_prestep_6098510',
    'call_apply_609c8c0', 'call_setter_6099e70'.
    """
    actions = []
    if map_empty:
        if config_byte3 == 0:
            return ["return_kok"]
        actions.append("call_slot5")
        if apply_status_ok:
            return actions + ["return_kok"]
        if s0_nonempty:
            return actions + ["call_setter_6099e70"]
        return actions + ["return_kok"]
    if config_byte0 == 0:
        actions.append("delimiter_prestep")
        actions.append("call_prestep_6098510")
    actions.append("call_apply_609c8c0")
    if config_byte3 != 0:
        return actions + ["call_setter_6099e70"]
    if apply_status_ok:
        return actions + ["return_kok"]
    if s0_nonempty:
        return actions + ["call_setter_6099e70"]
    return actions + ["return_kok"]


def nullchecked_entry(object_is_null, map_empty):
    """Model of 0x609e2d0.

    Returns (status, forwarded_to_slot9).
    """
    if object_is_null:
        if map_empty:
            return Status(0), False
        return Status(NULL_OBJECT_CODE, NULL_OBJECT_MESSAGE), False
    return Status(0), True


def map_find(entries, key):
    """Model of 0x609a1b0: returns the value for key, or None."""
    return entries.get(key)


def map_erase(entries, key):
    """Model of 0x609a2f0: remove key; returns True when it was present."""
    if key in entries:
        del entries[key]
        return True
    return False


def map_clear(entries):
    """Model of 0x5d5b300: drop every entry."""
    entries.clear()


def find_uses_linear_scan(element_count):
    """0x609a1b0 walks the node list while element_count <= 20."""
    return element_count <= FIND_LINEAR_MAX_ELEMENTS


def slot9_entry_arg5():
    """0x6097150 zeroes arg5 (r8) before forwarding to the tail."""
    return 0
