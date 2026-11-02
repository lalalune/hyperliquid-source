"""Model of node #94 function 0x514c1c0: post-order tree-node teardown (RE-001).

Evidence: research/work-items/RE-001-tree-node-teardown-94/ (RE-001).
A node is 0x48 bytes: next sibling at +0x10, first child at +0x18, and
a string member at +0x28 (pointer +0x28, length +0x30 never read here,
union +0x38: heap capacity, or the SSO buffer itself). Destroying a
node sized-deletes the heap string buffer with size capacity + 1 when
the pointer differs from the node's own +0x38 address, then
sized-deletes the node with size 0x48. destroy_list walks a +0x10
chain destroying each node's whole +0x18 child list first (post-order).
The wrapper at 0x514c520 is the same traversal entered from a
container's +0x10 head, so wrapper_teardown delegates to destroy_list.
Capacity overflow (capacity == 2**64 - 1) is not observed and not
modelled; a null head destroys nothing.
"""

NODE_SIZE = 0x48


def make_node(node_id, next_id=None, child_id=None,
              heap=False, buffer=None, capacity=0):
    """Build one node record for the model heap.

    heap=False means the string is SSO-stored (pointer == own +0x38),
    so no buffer delete is emitted. heap=True needs a buffer label
    and a capacity; the buffer delete size is capacity + 1.
    """
    return {'id': node_id, 'next': next_id, 'child': child_id,
            'heap': heap, 'buffer': buffer, 'capacity': capacity}


def _destroy_node(node, events):
    if node['heap']:
        events.append(('free_buffer', node['buffer'], node['capacity'] + 1))
    events.append(('free_node', node['id'], NODE_SIZE))


def destroy_list(head_id, nodes):
    """Destroy the +0x10 chain starting at head_id, post-order.

    Returns the ordered event list: ('free_buffer', label, size) and
    ('free_node', node_id, 0x48) tuples. nodes maps id -> node record.
    """
    events = []
    current = head_id
    while current is not None:
        node = nodes[current]
        if node['child'] is not None:
            events.extend(destroy_list(node['child'], nodes))
        nxt = node['next']
        _destroy_node(node, events)
        current = nxt
    return events


def teardown(head_id, nodes):
    """The 0x514c1c0 entry point: destroy_list starting at head_id."""
    return destroy_list(head_id, nodes)


def wrapper_teardown(container_head_id, nodes):
    """The 0x514c520 wrapper: destroy_list from a container's +0x10 head.

    The wrapper never destroys the container itself, only the list
    its +0x10 field heads; each list node is handled exactly as in
    destroy_list (children first, then the node).
    """
    return destroy_list(container_head_id, nodes)
