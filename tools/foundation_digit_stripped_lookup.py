#!/usr/bin/env python3
"""Model of node #94 digit-stripped table lookup at 0x514e160 (RE-001).

The window takes one string view (pointer + unsigned length), strips
its trailing ASCII decimal digits, and looks the stripped bytes up in
the global table at 0x578af60, returning the matched node's payload
or None. The model is semantic: nodes and tables are plain Python
values, and the payload is returned as an opaque object, exactly as
the binary returns a pointer to node + 0x28 without interpreting it.

Table layout (from research/work-items/RE-001-digit-stripped-lookup-94):
table buckets pointer +0x00, bucket count +0x08, global head +0x10,
size +0x18; node next +0x00, key pointer +0x08, key length +0x10,
payload +0x28, cached hash +0x70. When the size at +0x18 is greater
than 20 the hash-bucket path is used, otherwise the linear path.
"""

import os
import subprocess
import sys

HASH_SEED = 0xC70F6907
LINEAR_THRESHOLD = 20


def strip_trailing_digits(view):
    """Remove trailing ASCII decimal digits from a byte string.

    A byte b is a digit when (b - 0x30) <= 9 unsigned, i.e. 0x30..0x39.
    Scanning stops at the first non-digit from the end, so an
    all-digit view strips to empty and an empty view stays empty.
    """
    end = len(view)
    while end > 0 and 0x30 <= view[end - 1] <= 0x39:
        end -= 1
    return view[:end]


def hash_bytes(data, seed=HASH_SEED):
    """MurmurHash64A as used by libstdc++ _Hash_bytes.

    Cross-checked against the VM's own libstdc++ _Hash_bytes at the
    packet seed for empty, 1-, 3-, 5-, 6- and 16-byte inputs (see the
    packet's records.json vectors). The target binary calls the hash
    through a PLT stub, so this validates the implementation against
    the library algorithm, not by executing the target binary.
    """
    mask = (1 << 64) - 1
    m = 0xC6A4A7935BD1E995
    r = 47
    n = len(data)
    h = (seed ^ ((n * m) & mask)) & mask
    i = 0
    while i + 8 <= n:
        k = int.from_bytes(data[i:i + 8], "little")
        k = (k * m) & mask
        k ^= k >> r
        k = (k * m) & mask
        h ^= k
        h = (h * m) & mask
        i += 8
    rem = data[i:]
    if rem:
        k = 0
        for j, b in enumerate(rem):
            k |= b << (8 * j)
        h ^= k
        h = (h * m) & mask
    h ^= h >> r
    h = (h * m) & mask
    h ^= h >> r
    return h


class Node:
    """One table node: a key, its cached hash, and an opaque payload."""

    def __init__(self, key, cached_hash, payload):
        self.key = bytes(key)
        self.cached_hash = cached_hash
        self.payload = payload


class Table:
    """A table snapshot: bucket chains, global order, and size.

    ``buckets`` maps a bucket index to the chain of nodes in walk
    order (the first entry is the node reached by dereferencing the
    bucket slot once). ``head`` is the global list order used by the
    linear path. ``size`` is the table size at +0x18 that selects
    the path, and ``bucket_count`` is the divisor at +0x08.
    """

    def __init__(self, buckets, head, size, bucket_count):
        self.buckets = dict(buckets)
        self.head = list(head)
        self.size = size
        self.bucket_count = bucket_count


def _bucket_lookup(stripped, table, search_hash):
    if table.bucket_count <= 0:
        raise ValueError("bucket count must be positive on the hash path")
    bucket = search_hash % table.bucket_count
    chain = table.buckets.get(bucket, [])
    for index, node in enumerate(chain):
        if index > 0 and node.cached_hash % table.bucket_count != bucket:
            # The binary ends the chain with 0 when a later node's
            # cached hash falls in a different bucket.
            return None
        if node.cached_hash == search_hash and node.key == stripped:
            return node.payload
    return None


def _linear_lookup(stripped, table):
    for node in table.head:
        if node.key == stripped:
            return node.payload
    return None


def lookup(view, table, hash_fn=None):
    """Look a view up in a table snapshot, as 0x514e160 does.

    ``view`` is the raw input bytes (the binary's view struct holds
    a pointer and a length; the model takes the bytes directly).
    Returns the matched node's payload, or None when nothing matches.
    ``hash_fn`` defaults to :func:`hash_bytes`; tests may inject a
    stub to pin bucket placement without depending on the hash.
    """
    stripped = strip_trailing_digits(bytes(view))
    if table.size > LINEAR_THRESHOLD:
        if hash_fn is None:
            hash_fn = hash_bytes
        return _bucket_lookup(stripped, table, hash_fn(stripped))
    return _linear_lookup(stripped, table)


def excerpt_matches(binary, start, stop, path, cwd=None):
    """Check a shipped objdump excerpt against a fresh objdump run.

    Returns True when the objdump output for [start, stop) is
    byte-identical to the file at ``path``. This is the independent
    excerpt check: the packet's verify.py checks carve SHAs, while
    this checks the excerpt text itself against the binary. Note
    objdump prints the binary path as invoked in its header, so
    callers must invoke it with the same path spelling the excerpts
    were generated with (``work/hl-node-94.bin`` from the repo root).
    """
    result = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, binary],
        capture_output=True, text=True, cwd=cwd)
    if result.returncode != 0:
        return False
    with open(path) as f:
        return f.read() == result.stdout


def check_packet(packet_dir, binary):
    """Run the packet's verify.py against a binary; return its output."""
    result = subprocess.run(
        [sys.executable, os.path.join(packet_dir, "verify.py"),
         "--binary", binary],
        capture_output=True, text=True)
    return result
