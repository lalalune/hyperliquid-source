"""Model of node #115 routine 0x5d8ce30: indexed table entry.

Pinned from the digest-verified node #115 binary
(SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301).

The routine takes two arguments: an owner object pointer in rdi
and an index in rsi. It returns one qword:

1. Table bounds: load the table base from owner +0x988 and the
   table end from owner +0x990. If the two are equal, the table
   is empty: return null at once, without reading any entry.
2. Entry load: otherwise return the qword at base + index * 16
   -- the first qword of the index-th 16-byte entry.

The routine writes nothing and makes no call. Its one consumer
is the fallback lookup at 0x5d52b60, which calls it at site
0x5d52b76 after moving its own rsi into rdi and its rdx into
rsi, and returns a non-null result at once.

NOT modelled: what the owner object, the table, or the returned
entry qword denote, or what the 16-byte entries contain past
their first qword. The model represents the two table slots by
object identity: the caller passes the same object for both
fields exactly when the binary's two slots hold the same
pointer, and distinct objects otherwise. A null owner raises,
matching the binary's unconditional reads of +0x988/+0x990.
An out-of-range or negative index is not given a binary
behaviour here: the binary reads past the table unchecked, and
the model raises instead.
"""

TABLE_BEGIN_OFFSET = 0x988
TABLE_END_OFFSET = 0x990
ENTRY_STRIDE = 16
CONSUMER_ROUTINE = 0x5D52B60
CONSUMER_SITE = 0x5D52B76


def table_entry(owner, index):
    """Run the pinned behaviour.

    owner: dict with "table_begin_0x988" (list of entry qwords,
    or None) and "table_end_0x990" (the same object as the
    begin list exactly when the binary's slots are equal, or
    None). Each list element stands for the first qword of one
    16-byte entry.
    index: integer entry index.

    Returns the entry qword, or None when the table is empty.
    """
    if owner is None:
        raise ValueError("null owner pointer")
    begin = owner["table_begin_0x988"]
    end = owner["table_end_0x990"]
    if begin is end:
        return None
    if begin is None:
        raise ValueError("null table base with a non-equal end")
    if index < 0:
        raise ValueError("negative index")
    try:
        return begin[index]
    except IndexError:
        raise ValueError("index out of range")
