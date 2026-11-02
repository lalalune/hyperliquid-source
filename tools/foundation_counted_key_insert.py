"""Python model of node #94 0x5160940: mutex-guarded counted-key
insert-or-increment over an ascending-order vector of (key, count)
pairs.

Bound to work/hl-node-94.bin (node #94, SHA-256
3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f);
evidence packet: research/work-items/RE-001-counted-key-insert-94/.

The window (0x5160940..0x5160aca) holds a vector at outer +0x00
(begin) / +0x08 (end) / +0x10 (capacity) of 16-byte elements (key
+0x00, count +0x08) and a mutex at +0x18. Keys are compared
unsigned. On a match the count is incremented by 1 (addq, wrapping
modulo 2^64). On a miss a (key, 1) pair is inserted so the vector
stays in ascending key order. When end equals capacity the
window calls the growth helper 0x5160790 with (outer, pair
pointer) instead of inserting itself; that contract is exposed
here as the caller-supplied ``grow`` callback, which must insert
the pair and return its position.

Comparison direction (AT&T syntax): ``cmp %rbx,-0x10(%rax)``
computes element minus key, so ``jae`` is taken while the element
is greater than or equal to the key. The scan therefore steps
toward the begin while elements exceed the key, and inserts after
the first element smaller than the key — ascending order.
"""

MASK64 = (1 << 64) - 1


class NeedsGrowth(Exception):
    """Raised when an insert needs room and no grow callback was given."""


class LockFailed(Exception):
    """Mirrors the window's system_error throw on a nonzero lock result."""


class CountedKeyTable:
    """The outer struct of 0x5160940: vector plus mutex."""

    def __init__(self, capacity, pairs=None):
        self.pairs = [list(pair) for pair in (pairs or [])]
        self.capacity = capacity
        self.locked = False
        # Test hook mirroring a nonzero pthread_mutex_lock result.
        self.lock_fail = False

    def __len__(self):
        return len(self.pairs)

    def _lock(self):
        if self.lock_fail:
            raise LockFailed("mutex lock returned nonzero")
        self.locked = True

    def _unlock(self):
        self.locked = False

    def keys(self):
        return [key for key, _ in self.pairs]

    def insert_or_increment(self, key, grow=None):
        """Insert (key, 1) or increment the existing count.

        Returns (outcome, position) where outcome is "incremented",
        "inserted", or "grown". The mutex is unlocked on every exit,
        including the lock-failure and growth paths, mirroring the
        window's epilogue and its exception cleanup.
        """
        if not 0 <= key <= MASK64:
            raise ValueError("key must be an unsigned 64-bit value")
        self._lock()
        try:
            # Walk from the end toward the begin, as the window does.
            # AT&T cmp %rbx,mem computes mem - key: jae (taken) means
            # the element is >= the key, so step down; jae not taken
            # means the element is < the key, so insert after it.
            for index in range(len(self.pairs) - 1, -1, -1):
                other = self.pairs[index][0]
                if key == other:
                    count = self.pairs[index][1]
                    self.pairs[index][1] = (count + 1) & MASK64
                    return ("incremented", index)
                if key > other:
                    # Insert immediately after this element.
                    position = index + 1
                    break
            else:
                # Smaller than every element: insert at the begin.
                position = 0
            if len(self.pairs) == 0:
                position = 0
            if len(self.pairs) >= self.capacity:
                if grow is None:
                    raise NeedsGrowth("vector is full and no grow given")
                grown_at = grow(self, key)
                return ("grown", grown_at)
            self.pairs.insert(position, [key, 1])
            return ("inserted", position)
        finally:
            self._unlock()
