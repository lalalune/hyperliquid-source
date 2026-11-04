"""Python model of the node #115 three-array string teardown routine
at 0x5d54fc0 (RE-001 work item).

The routine frees, in order, three vectors of 32-byte strings held in
one holder:

  vector A: begin +0x50, end +0x58, capacity end +0x60
  vector B: begin +0x38, end +0x40, capacity end +0x48
  vector C: begin +0x08, end +0x10, capacity end +0x18

For each element, a data pointer equal to the element's own +0x10
address means a short string (inline buffer) and frees nothing; any
other data pointer is freed with the sized delete using capacity + 1
(the heap allocation size including the terminating NUL). After a
vector's elements, its buffer is freed with (begin, capacity end
minus begin) unless begin is null. The routine writes nothing back
to the holder.

A vector is a ``(begin_present, elements, capacity_bytes)`` triple
where ``begin_present`` is False for a null vector, ``elements`` is a
list of ``(is_heap, capacity)`` pairs (``capacity`` ignored for short
strings), and ``capacity_bytes`` is the allocated buffer size. A free
is recorded as ``("elem", vector, index, size)`` or
``("buffer", vector, size)``.
"""

VECTORS = ("A", "B", "C")


def teardown(holder):
    """Simulate the routine and return the ordered list of frees."""
    frees = []
    for name in VECTORS:
        begin_present, elements, capacity_bytes = holder[name]
        if not begin_present:
            if elements:
                raise ValueError(f"vector {name}: null begin with elements")
            continue
        for index, (is_heap, capacity) in enumerate(elements):
            if is_heap:
                frees.append(("elem", name, index, capacity + 1))
        frees.append(("buffer", name, capacity_bytes))
    return frees
