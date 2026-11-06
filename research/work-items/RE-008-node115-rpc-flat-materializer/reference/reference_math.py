"""High-level conditional value reference, not captured-code execution.

Uses supplied byte strings and opaque integer values only. No midpoint loop,
PC/register/memory state, native addresses, callback answers or binary decoder.
Native correspondence remains subject to ROOT-RPC-CONTRACT.v3.md premises.
Resource/format limits belong to the separately chosen driver transport.
"""
from dataclasses import dataclass

U64_MAX = (1 << 64) - 1


class DomainError(ValueError):
    """Safe host input refusal; never a claim about a native error result."""


def key_check(key):
    if type(key) is not bytes or len(key) != 32:
        raise DomainError('key must be exactly 32 supplied bytes')


@dataclass(frozen=True)
class Row:
    key: bytes
    value: int

    def __post_init__(self):
        key_check(self.key)
        if type(self.value) is not int or not 0 <= self.value <= U64_MAX:
            raise DomainError('row value must be a u64 integer')


@dataclass(frozen=True)
class Found:
    logical_index: int
    physical_index: int
    value: int


@dataclass(frozen=True)
class Missing:
    insertion_index: int


@dataclass(frozen=True)
class Ring:
    physical_rows: tuple
    head: int
    live_len: int

    def __post_init__(self):
        if type(self.physical_rows) is not tuple or any(type(r) is not Row for r in self.physical_rows):
            raise DomainError('physical allocation must be a tuple of Rows')
        c = len(self.physical_rows)
        if type(self.head) is not int or type(self.live_len) is not int:
            raise DomainError('header fields must be integers')
        if not 0 <= self.live_len <= c:
            raise DomainError('live length must be within capacity')
        if (c == 0 and self.head != 0) or (c > 0 and not 0 <= self.head < c):
            raise DomainError('head must be zero for empty allocation, otherwise below capacity')
        live = self.logical_rows()
        if any(row.value == 0 for _, row in live):
            raise DomainError('live values must be nonzero')
        if any(left[1].key > right[1].key for left, right in zip(live, live[1:])):
            raise DomainError('live keys must be nondecreasing')

    @property
    def capacity(self):
        return len(self.physical_rows)

    def logical_rows(self):
        # Empty allocation has no live rows, so modulo zero is never evaluated.
        return tuple(((self.head+i) % self.capacity,
                      self.physical_rows[(self.head+i) % self.capacity])
                     for i in range(self.live_len))

    def search(self, query):
        key_check(query)
        live = self.logical_rows()
        equal = [i for i, (_, row) in enumerate(live) if row.key == query]
        if not equal:
            return Missing(sum(row.key < query for _, row in live))
        seam = self.capacity - self.head
        if self.live_len > seam and live[seam][1].key == query:
            selected = seam
        else:
            selected = equal[-1]
        physical, row = live[selected]
        return Found(selected, physical, row.value)

    def materialize(self, queries):
        # All-hit value predicate. This intentionally specifies no callback or
        # read-count trace, including whether later queries are inspected.
        results = tuple(self.search(query) for query in queries)
        if any(isinstance(result, Missing) for result in results):
            return None
        return tuple(result.value for result in results)
