"""Python model of node #115's predicate-gated drain 0x5f14000 and its
transfer callee 0x5f13e00.

Implements the semantics pinned by
research/work-items/RE-001-predicate-drain-115. The predicate
(0x5f13240, mapped by #2182), the aggregate (0x5f0e2d0, mapped by
#2046) and the vector-grow step (0x5d90f50, by contract) are taken as
injected callables rather than re-implemented, because they are
mapped elsewhere or not read here.

State shapes (all plain dicts/lists, no binary layout):

- An object is ``{"list2": [...], "size": int}``: ``list2`` holds the
  payloads of the second list in first-to-last order, and ``size``
  mirrors the binary's [object + 0x28] field.
- A collection is ``{"count": int, "inline": [...], "vector": [...]}``:
  ``count`` mirrors [collection], ``inline`` the buffer reached
  through collection + 0x48, ``vector`` the overflow vector at
  collection + 0x50.
- A payload is ``{"refcount": int}`` mirroring payload + 0x70.
- The subtraction target ``*[object + 0x48]`` is a one-element list
  holding the current value.

Model-side guards (not binary behavior, stated explicitly): the
binary has no consistency check between the size field and the list,
and it would fault on a dangling pointer. ``drain`` raises ValueError
when the size field disagrees with the list length so the Python model
always stays consistent; tests pin the guard.
"""

INLINE_CAPACITY = 7  # inline path while count <= 7 (indices 0..7)


def transfer(subtract_target, collection, payload, aggregate):
    """Transfer one payload; return True when the transfer happened.

    Decrements the payload refcount; a still-positive result returns
    at once with no other effect. Otherwise appends the payload to the
    collection (inline while count <= 7, overflow vector above that)
    and subtracts ``aggregate(payload)`` from the subtraction target.
    """
    payload["refcount"] -= 1
    if payload["refcount"] > 0:
        return False
    count = collection["count"]
    if count > INLINE_CAPACITY:
        collection["vector"].append(payload)
    else:
        collection["inline"].append(payload)
        collection["count"] = count + 1
    subtract_target[0] -= aggregate(payload)
    return True


def drain(obj, collection, subtract_target, predicate_arg, predicate,
          aggregate):
    """Pop-back drain loop; return 1 if anything was popped, else 0.

    While ``predicate(obj, predicate_arg)`` stays true and the second
    list is non-empty, pops the LAST node, decrements the size field,
    and transfers its payload. The binary deletes each popped node
    (0x18 bytes) after unhooking it; the model drops it from the list,
    which is the same observable effect.
    """
    if obj["size"] != len(obj["list2"]):
        raise ValueError("size field disagrees with list length")
    popped = 0
    while predicate(obj, predicate_arg):
        if not obj["list2"]:
            break
        payload = obj["list2"].pop()
        obj["size"] -= 1
        popped = 1
        transfer(subtract_target, collection, payload, aggregate)
    return popped
