"""Python model of the node #115 parse-then-apply wrapper 0x60c1bb0 (RE-001).

The wrapper (FDE 0x60c1bb0..0x60c1cc5) parses an option string into a
temporary stack map and then applies the map to an options struct:
  1. build a stack unordered_map<string,string> (single bucket),
  2. parse via the map parser 0x60c1190 (algorithm pinned by #4320/#4349:
     strip, unwrap outer braces while length > 2, split on ';', each
     segment needs '=', duplicate keys last-wins through operator[]),
  3. on parse failure copy the parse Status into *out and destroy the
     temporary map (the apply stage is never reached),
  4. on parse success apply via the apply loop 0x60c18b0 (#4237) with the
     exact six-arg forwarding, then destroy the temporary map.

Status codes follow RocksDB: kOk 0, kNotFound 1, kInvalidArgument 4.
"""

OK = 0
NOT_FOUND = 1
INVALID_ARGUMENT = 4

MISMATCHED = "Mismatched key value pair, '=' expected"
UNEXPECTED_CHAR = "Unexpected char in key"
EMPTY_KEY = "Empty key found"
UNRECOGNIZED = "Unrecognized option"
NOT_FOUND_OPTION = "Could not find option"

# Verification value 4: the per-entry apply returns kOk immediately and
# never parses or dumps the entry (#4311).
VERIFICATION_SKIP = 4


class Status:
    """A 16-byte RocksDB Status: code + message (ownership transfers)."""

    def __init__(self, code=OK, message=""):
        self.code = code
        self.message = message

    @property
    def ok(self):
        return self.code == OK

    def __repr__(self):
        return f"Status({self.code}, {self.message!r})"


def parse_kv_text(text):
    """Model of the 0x60c1190 map parser contract (#4320/#4349).

    Returns (Status, entries dict). The sequential find_first_of scan:
    a segment with no special char at all -> MISMATCHED; a ';' (or '{'
    / '}') before the '=' -> UNEXPECTED_CHAR; an empty key ->
    EMPTY_KEY. Duplicate keys overwrite (operator[] semantics).
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
            return Status(INVALID_ARGUMENT, MISMATCHED), {}
        if body[j] != "=":
            return Status(INVALID_ARGUMENT, UNEXPECTED_CHAR), {}
        if j == pos:
            return Status(INVALID_ARGUMENT, EMPTY_KEY), {}
        key = body[pos:j].strip()
        k = j + 1
        while k < n and body[k] != ";":
            k += 1
        entries[key] = body[j + 1:k].strip()
        pos = k + 1
    return Status(OK), entries


def apply_loop(parsed, type_info, options_base_first_byte, arg5, overflow):
    """Model of the apply loop 0x60c18b0 (#4237) as the wrapper drives it.

    parsed: the temporary map (insertion-ordered dict).
    type_info: name -> record dict; only membership and the
        'verification' field are consulted here.
    options_base_first_byte: the byte at options_base + 0x00.
    arg5: the wrapper's opaque arg5; the per-entry apply requires it
        non-null on the value-parse path (else kNotFound
        'Could not find option' + key). Pass None to model a null arg5.
    overflow: dict or None. Non-null: unknown keys are diverted into
        it (operator[] assign). None: unknown keys error or skip.

    Returns (Status, applied dict, overflow dict-or-None). Entries
    applied before a failure stay applied; the loop stops at the first
    failure.
    """
    applied = {}
    for key, value in parsed.items():
        record = type_info.get(key)
        if record is not None:
            if record.get("verification", 0) == VERIFICATION_SKIP:
                continue
            if arg5 is None:
                return Status(NOT_FOUND, NOT_FOUND_OPTION + key), applied, overflow
            applied[key] = value
            continue
        if overflow is not None:
            overflow[key] = value
            continue
        if options_base_first_byte != 0:
            continue
        return Status(NOT_FOUND, UNRECOGNIZED + key), applied, overflow
    return Status(OK), applied, overflow


def parse_then_apply(input_text, type_info, options_base_first_byte=0,
                     arg5="context", overflow=None):
    """Model of the wrapper 0x60c1bb0 itself.

    Returns (Status, applied dict, overflow dict-or-None,
    temp_map_destroyed). The temporary map is destroyed on both paths
    (the map dtor 0x5d36110 runs at 0x60c1c53 either way); on parse
    failure the parse Status is copied verbatim into out and the apply
    stage is never reached, so applied is empty.
    """
    parse_status, temp_map = parse_kv_text(input_text)
    if not parse_status.ok:
        # Failure path (0x60c1c33): copy the parse Status into *out,
        # destroy the temporary map, return out.
        return parse_status, {}, overflow, True
    status, applied, overflow = apply_loop(
        temp_map, type_info, options_base_first_byte, arg5, overflow)
    # Success path (0x60c1c92): the apply loop writes into out
    # directly; the temporary map is destroyed afterwards.
    return status, applied, overflow, True
