"""Pure byte-grammar authority; no ELF/opcode/PC/register evaluation."""


def utf8_relation(raw):
    """Return (valid_up_to, optional_error_length), or None on success.

    Each accepted form is a shortest encoding of a Unicode scalar. Error
    length counts the valid prefix of the failing scalar before a present
    wrong continuation; a missing continuation is represented by None.
    """
    offset = 0
    while offset < len(raw):
        lead = raw[offset]
        if lead <= 0x7F:
            offset += 1
            continue
        if 0xC2 <= lead <= 0xDF:
            continuations = [(0x80, 0xBF)]
        elif 0xE0 <= lead <= 0xEF:
            second = (0xA0, 0xBF) if lead == 0xE0 else (0x80, 0x9F) if lead == 0xED else (0x80, 0xBF)
            continuations = [second, (0x80, 0xBF)]
        elif 0xF0 <= lead <= 0xF4:
            second = (0x90, 0xBF) if lead == 0xF0 else (0x80, 0x8F) if lead == 0xF4 else (0x80, 0xBF)
            continuations = [second, (0x80, 0xBF), (0x80, 0xBF)]
        else:
            return offset, 1
        for position, (lower, upper) in enumerate(continuations, start=1):
            if offset + position == len(raw):
                return offset, None
            if not lower <= raw[offset + position] <= upper:
                return offset, position
        offset += len(continuations) + 1
    return None


def python_relation(raw):
    """Independent standard Unicode decoder check, separate from the authority."""
    try:
        raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        length = None if error.reason == "unexpected end of data" else error.end - error.start
        return error.start, length
    return None
