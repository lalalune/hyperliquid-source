"""Python model of the node #115 keyed lookup finalize pair:
the wrapper 0x606c680 and the lookup 0x5d52660 it calls.

The wrapper takes a node in rdi and two values, reads the
key pointer at node +0x68, and, when the key is present,
calls the lookup with (key, value1, value2, &node +0x08,
&node +0x20), storing the lookup's return byte at node
+0x60. The lookup searches the key object's tree for the
smallest field >= value1 and accepts it only when it is
unsigned-below value2; on acceptance it writes the matched
field to *out1 and calls the payload callee with (out2,
candidate + 0x28), then releases the auxiliary structure.
The auxiliary callee, the release callee, and the payload
callee are opaque here: only their argument lists, order,
and presence on each path are pinned. Comparisons are
unsigned 64-bit, as the binary's jb/jae instructions show.
The model assumes a finite tree and raises on a null node
or key, mirroring the binary's unconditional dereferences.
"""

WRAPPER = 0x606C680
LOOKUP = 0x5D52660
WRAPPER_FDE = (0x606C680, 0x606C6A5)
LOOKUP_FDE = (0x5D52660, 0x5D52765)
KEY_OFFSET = 0x68
OUT1_OFFSET = 0x08
OUT2_OFFSET = 0x20
FLAG_OFFSET = 0x60
TREE_HEADER_OFFSET = 0xCA8
TREE_ROOT_OFFSET = 0xCB0
AUX_OFFSET = 0x988
NODE_LEFT_OFFSET = 0x10
NODE_RIGHT_OFFSET = 0x18
NODE_KEY_OFFSET = 0x20
PAYLOAD_OFFSET = 0x28
AUX_CALLEE = 0x606CA40
AUX_RELEASE_CALLEE = 0x60D52F0
PAYLOAD_CALLEE = 0x5D4E140
SLOT_REPLACE_CALL = 0x5D4CD33
TAIL_JUMP_SITE = 0x606C6D6
TAIL_JUMP_CALLER_FDE = (0x606C6B0, 0x606C6DB)
TAIL_HELPER = 0x606C190


class TreeNode:
    """One tree node: compared field plus left/right children."""

    def __init__(self, key, left=None, right=None):
        self.key = key
        self.left = left
        self.right = right


class Key:
    """A key object: the tree root plus a header sentinel.

    The header sentinel is a distinct object standing for the
    header address at key +0xca8; the walk returns the
    not-found result when the candidate is still the sentinel.
    """

    def __init__(self, root=None):
        self.root = root
        self.header = object()


class Node:
    """A node being finalized: its fields plus its key object."""

    def __init__(self, key=None):
        self.key = key
        self.fields = {}


class RecordingHooks:
    """Stand-in callees that record every call in order."""

    def __init__(self):
        self.events = []

    def aux_lookup(self, aux, value1, value2, node):
        self.events.append(("aux_lookup", aux, value1, value2, node,
                            OUT1_OFFSET, node, OUT2_OFFSET))

    def aux_release(self, aux):
        self.events.append(("aux_release", aux))

    def payload(self, node, candidate):
        self.events.append(("payload", node, OUT2_OFFSET, candidate,
                            PAYLOAD_OFFSET))


def lookup_52660(key, value1, value2, node, hooks,
                 out1_present=True, out2_present=True):
    """Run the 0x5d52660 lookup; return 1 on a range match, else 0.

    node supplies the out addresses (+0x08 and +0x20) and
    receives the matched field at +0x08 on success. Passing
    out1_present or out2_present as False models a null out
    pointer, which returns 0 before any callee runs.
    """
    if key is None:
        raise ValueError("null key")
    if not out1_present or not out2_present:
        return 0
    hooks.aux_lookup(key, value1, value2, node)
    current = key.root
    candidate = key.header
    while current is not None:
        if current.key < value1:
            current = current.right
        else:
            candidate = current
            current = current.left
    if candidate is key.header:
        hooks.aux_release(key)
        return 0
    if candidate.key >= value2:
        hooks.aux_release(key)
        return 0
    node.fields[OUT1_OFFSET] = candidate.key
    hooks.payload(node, candidate)
    hooks.aux_release(key)
    return 1


def finalize_6c680(node, value1, value2, hooks):
    """Run the 0x606c680 wrapper; return the flag byte stored.

    A null key stores 0 at node +0x60 and calls nothing.
    Otherwise the lookup result (0 or 1) is stored at
    node +0x60 and returned.
    """
    if node is None:
        raise ValueError("null node")
    key = node.key
    if key is None:
        node.fields[FLAG_OFFSET] = 0
        return 0
    result = lookup_52660(key, value1, value2, node, hooks)
    node.fields[FLAG_OFFSET] = result
    return result
