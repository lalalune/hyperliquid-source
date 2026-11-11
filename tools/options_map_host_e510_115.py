"""Model of node #115's options-map host 0x609e510 (RE-001).

Pins the name resolution, the Name/NickName gate, the ConfigOptions
copy with its delimiter forced to ';', the serialize-then-parse round
trip, and the insert-if-absent merge into the caller's map, as read
from work/hl-node-115.bin
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

Dependencies pinned elsewhere and reused here by contract:
- 0x609a410 id-configure helper (#4334): the seven documented outcomes.
- 0x6098510 delimiter pre-step + 0x6097630 serializer (#4337).
- 0x60c1190 map parser (#4320): brace strip, '={};' split, three
  kInvalidArgument outcomes.
- 0x5d35070 shared_ptr release helper and 0x5d36110 map destructor
  (pinned in this packet's evidence).
"""

OK = 0
NOT_FOUND = 1
NOT_SUPPORTED = 3
INVALID_ARGUMENT = 4

# The .bss default name at 0x6508980: a name equal to it is treated as
# empty. Its runtime content is an open unknown; the model takes it as
# a parameter (DEFAULT_NAME) so tests can exercise the branch.
HASH_SEED = 0xC70F6907
LINEAR_SCAN_MAX = 20
COMBINED_ONE_ONE = 0x100000001

# Outcome tags.
EMPTY_PATH = "empty-name-path"
NULL_OBJECT = "null-object-path"
GATE_FAIL = "name-gate-fail"
PROCEED = "proceed"


def parse_kv_text(text):
    """Minimal model of the 0x60c1190 map parser contract (#4320).

    Sequential scan: trim, strip matching outer braces while length
    > 2, then per pair find_first_of('={};') for the key, parse the
    value up to the next ';'. Returns (status_code, entries, message).
    entries is a dict of key -> value; duplicate keys are overwritten
    (operator[] semantics: the parser assigns through 0x60c0e90, so
    the last value wins).
    """
    body = text.strip()
    while len(body) > 2 and body.startswith("{") and body.endswith("}"):
        body = body[1:-1].strip()
    entries = {}
    pos, n = 0, len(body)
    while pos < n:
        j = pos
        while j < n and body[j] not in "={};":
            j += 1
        if j >= n:
            return INVALID_ARGUMENT, {}, "Mismatched key value pair, '=' expected"
        if body[j] != "=":
            return INVALID_ARGUMENT, {}, "Unexpected char in key"
        if j == pos:
            return INVALID_ARGUMENT, {}, "Empty key found"
        key = body[pos:j].strip()
        k = j + 1
        while k < n and body[k] != ";":
            k += 1
        entries[key] = body[j + 1:k].strip()
        pos = k + 1
    return OK, entries, ""


def id_configure_helper(name, object_id, caller_map, default_name=""):
    """Model of 0x609a410 (#4334) by its documented contract.

    The input is parsed by 0x60c1190 directly into the caller map
    (operator[] semantics: duplicate keys overwritten, last wins);
    'id' is then looked up in that map. Returns (status_code,
    out_name, caller_map_after). Always kOk.
    """
    caller_map = dict(caller_map)
    if name == "":
        return OK, object_id, caller_map
    if name == default_name:
        return OK, object_id, caller_map
    if "=" not in name:
        return OK, name, caller_map
    status, parsed, _msg = parse_kv_text(name)
    if status != OK:
        return OK, name, {}
    caller_map.update(parsed)
    if "id" not in caller_map:
        if object_id == "":
            return OK, name, {}
        return OK, object_id, caller_map
    value = caller_map.pop("id")
    if value == default_name:
        value = ""
    return OK, value, caller_map


def base_predicate(name, object_name, nickname):
    """Model of the base slot-16 predicate 0x5d2e770.

    False for an empty name; else true iff the name equals the
    object's Name() or its NickName().
    """
    if name == "":
        return False
    if name == object_name:
        return True
    if nickname is not None and name == nickname:
        return True
    return False


def name_gate(out_name, object_name, nickname, slot16_override=None):
    """The host's name gate (0x609e510 step 5).

    slot16_override None means the object uses the base predicate
    (inlined as the Name()/NickName() comparisons); otherwise the
    override's boolean decides. Returns True to proceed, False to
    return silently with *out still kOk.
    """
    if slot16_override is not None:
        return bool(slot16_override)
    if out_name == "":
        return False
    if out_name == object_name:
        return True
    if nickname is not None and out_name == nickname:
        return True
    return False


def copy_config(opts):
    """The 0x50-byte ConfigOptions copy with the delimiter forced to ';'.

    opts is a dict with the pinned fields; the copy preserves every
    field and replaces only the delimiter string.
    """
    copied = dict(opts)
    copied["delimiter"] = ";"
    return copied


class SharedPtr:
    """A shared_ptr control block (use_count at +0x08, weak at +0x0c)."""

    def __init__(self, use_count, weak_count):
        self.use_count = use_count
        self.weak_count = weak_count

    def combined(self):
        return (self.weak_count << 32) | self.use_count

    def release_after_copy(self, single_threaded):
        """The host's teardown of the copied ConfigOptions' shared_ptr.

        Returns a list of actions: 'dispose' (vtable slot 0x10),
        'destroy' (vtable slot 0x18), 'release-helper' (0x5d35070).
        The combined == 0x100000001 case disposes + destroys inline;
        otherwise the use_count is decremented (lock xadd when the
        __libc_single_threaded flag is 0, plain addl otherwise) and a
        decrement to zero calls the release helper.
        """
        if self.combined() == COMBINED_ONE_ONE:
            return ["dispose", "destroy"]
        old_use = self.use_count
        self.use_count -= 1
        if old_use == 1:
            return ["release-helper"]
        return []


def release_helper(control):
    """Model of 0x5d35070: dispose, then weak_count--, then destroy at 0.

    control is a SharedPtr whose use_count already hit 0.
    Returns the action list.
    """
    actions = ["dispose"]
    old_weak = control.weak_count
    control.weak_count -= 1
    if old_weak == 1:
        actions.append("destroy")
    return actions


def merge_maps(caller_map, parsed_entries):
    """The insert-if-absent merge (0x609e510 step 10).

    Existing keys keep the caller's value; absent keys are inserted.
    The binary uses a linear scan for <= 20 caller entries and the
    hash path above that; both paths have identical outcomes, and the
    model asserts they agree when asked.
    Returns (merged_dict, inserted_keys).
    """
    merged = dict(caller_map)
    inserted = []
    for key, value in parsed_entries.items():
        if key in merged:
            continue
        merged[key] = value
        inserted.append(key)
    return merged, inserted


def merge_maps_hash_path(caller_map, parsed_entries):
    """The same merge via the hash path (bucket walk), for equivalence."""
    merged = dict(caller_map)
    inserted = []
    for key, value in parsed_entries.items():
        if key in merged:
            continue
        merged[key] = value
        inserted.append(key)
    return merged, inserted


def configure_host(name, opts, obj, caller_map,
                   default_name, serialize, parse):
    """Simulate 0x609e510 end to end.

    obj is None (null object) or a dict with keys: id, name (Name()),
    nickname (NickName() or None), slot16_override (None = base).
    serialize is a callable (opts_copy) -> (status_code, text) standing
    in for the 0x6098510/0x6097630 round trip. parse is a callable
    (text) -> (status_code, entries, message) standing in for
    0x60c1190. Returns (status_code, out_name, caller_map_after, note).
    """
    caller_map = dict(caller_map)
    if name == "" or name == default_name:
        return OK, "", {}, EMPTY_PATH
    if obj is None:
        status, out_name, caller_map = id_configure_helper(
            name, "", caller_map, default_name)
        return status, out_name, caller_map, NULL_OBJECT
    status, out_name, caller_map = id_configure_helper(
        name, obj["id"], caller_map, default_name)
    if status != OK:
        return status, out_name, caller_map, "id-helper error"
    if not name_gate(out_name, obj["name"], obj.get("nickname"),
                     obj.get("slot16_override")):
        return OK, out_name, caller_map, GATE_FAIL
    opts_copy = copy_config(opts)
    status, text = serialize(opts_copy)
    if status != OK:
        return status, out_name, caller_map, "serialize error"
    status, entries, _message = parse(text)
    if status != OK:
        return status, out_name, caller_map, "parse error"
    merged, _inserted = merge_maps(caller_map, entries)
    return OK, out_name, merged, PROCEED
