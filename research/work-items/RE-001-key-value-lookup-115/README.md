# RE-001: map node #115 key-to-value lookup pair 0x5d8cf70 / 0x5d8ce90

## Bounded question

What does the lookup routine that open PR #2400's caller calls at
`0x5d69cb9` actually do — and what does the routine it tail-jumps
into return for the caller?

## Answer, stated literally

The routine at `0x5d8cf70` (FDE `0x5d8cf70..0x5d8d0ac`) is a
key lookup that resolves a key to a value pointer in two stages.
It takes a map object in `rdi` and a key in `rsi`, where the key
is a (pointer, length) pair: the key bytes live at `[key+0x00]`
and the length is the qword at `[key+0x08]`. The qword at
`map+0x18` selects the path: greater than 20 (unsigned) takes the
hash path, otherwise the small path.

### Stage 1, small path (count at most 20)

The node chain starts at the qword at `map+0x10`. Each node
carries its successor at `+0x00`, its key bytes pointer at
`+0x08` and its key length at `+0x10`. Nodes are scanned in chain
order; a node matches when its length equals the key length and
either the length is zero — no `memcmp` is issued for an empty
key — or `memcmp` over exactly that many bytes reports equal.
On a match, the dword at the node `+0x28` is the id handed to
stage 2. On exhaustion (a null head or a null successor) the
lookup returns 0 at once, without reaching stage 2.

### Stage 1, hash path (count greater than 20)

The key bytes and length are passed to the `_Hash_bytes` library
call with seed `0xc70f6907` (PLT `0x63f0ee0`; a library call, not
node logic — the model takes its result as an input). The bucket
count is the qword at `map+0x08` and the bucket array is the
qword at `map+0x00`; the bucket index is
`hash % bucket_count`. A zero slot means a miss. Otherwise the
slot points at a header whose `+0x00` field is the first node;
each node carries its successor at `+0x00`, its key bytes at
`+0x08`, its key length at `+0x10`, its id at `+0x28` (dword) and
its stored hash at `+0x30`. A node matches when its stored hash
equals the computed hash, its length equals the key length, and
either the length is zero or `memcmp` over exactly that many
bytes reports equal. Advancing past a node stops with a miss
when the successor is null or when the successor's stored hash
`% bucket_count` differs from the bucket index: the bucket's
nodes form one contiguous chain segment, and the scan never
looks past its end.

### Stage 2, value lookup at 0x5d8ce90 (FDE 0x5d8ce90..0x5d8cf24)

On a stage-1 match the key lookup restores its registers and
tail-jumps to `0x5d8ce90` at `0x5d8cfea`, passing the same map
object in `rdi` and the matched node's `+0x28` dword in `esi`
(zero-extended). So the key lookup's own return value is
whatever stage 2 returns. Stage 2's path is selected by the
qword at `map+0x50`: zero takes its small path, nonzero its
bucketed path.

- Small path: the value chain starts at the qword at `map+0x48`.
  Each value node carries its successor at `+0x00`, its id dword
  at `+0x08` and its value pointer at `+0x10`. The first node
  whose id equals the sought id yields its `+0x10` value; a null
  head or chain exhaustion returns 0. A matched node whose
  `+0x10` value is itself 0 therefore returns 0, exactly like a
  miss.
- Bucketed path: the bucket count is the qword at `map+0x40`
  and the bucket array is the qword at `map+0x38`; the bucket
  index is `id % bucket_count`. A zero slot means a miss.
  Otherwise the slot points at a header whose `+0x00` field is
  the first value node, scanned the same way as the key hash
  path: advancing stops with a miss when the successor is null
  or when the successor's id `% bucket_count` differs from the
  bucket index. On a match the value is the matched node's
  `+0x10` field, reached through its predecessor's `+0x00`
  field (for the first node, through the header).

So the complete observable behavior is: key in, value pointer
out, or 0 on any miss — a key miss, a bucket miss, a segment
end, or a value miss all return 0, and a zero value pointer is
indistinguishable from a miss.

## Census

Whole-file census (reproduced by `census.py` and re-run inside
`verify.py`): the key lookup has exactly nine direct call sites
and no tail jumps; the value lookup has exactly eight direct
call sites plus the one tail jump from the key lookup. Neither
routine has stored qwords or RELATIVE addends. The sites are
recorded by address in `callers.tsv`; caller semantics beyond
the calls are not claimed, except that the `0x5d69cb9` site's
branch behavior is the one open PR #2400 already documented
(lookup zero takes its null arm, nonzero falls through), and
the `0x5d8cf58` site sits in the wrapper at `0x5d8cf30`, which
calls the value lookup and stores its result but is not
modelled here.

## NOT claimed

What the map, its nodes, the keys or the ids denote; the
`_Hash_bytes` algorithm itself; any caller semantics beyond the
census; the wrapper at `0x5d8cf30`; or anything about the two
routines' behavior when a bucket header's `+0x00` field is null
or a bucket count is zero, which the binary dereferences /
divides without a check (the model raises for those inputs).

## Evidence and how it was produced

All results are bound to one artifact: `work/hl-node-115.bin`,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
matching the entry for `artifacts/node/115/hl-node` in
`provenance/artifacts.json`.

The disassembly excerpts in this packet are verbatim objdump
output, produced with commands of the form:

```
objdump -d --start-address=0x5d8cf70 --stop-address=0x5d8d0ac work/hl-node-115.bin
objdump -d --start-address=0x5d8ce90 --stop-address=0x5d8cf24 work/hl-node-115.bin
```

(see `export_excerpts.py`, which is committed in this packet and
regenerates every excerpt). Instruction-level detail lives only
in those raw excerpt text files, kept whole-function; the JSON
in this packet holds semantic records only, with no
per-instruction mnemonic list. Mnemonics such as `endbr64` in
the excerpts are genuine instructions present in the target
binary, not placeholders.

Files: `main.txt` (whole key lookup), `tail.txt` (whole value
lookup), `frames.txt` (FDE lines for both routines),
`relocations.txt` (empty: no RELATIVE record mentions either
routine), `callers.tsv` (the census sites), `records.json`
(semantic records), `export_excerpts.py`, `census.py`,
`verify.py`, `MANIFEST.sha256`.

## Verification

- Packet checker: `python3
  research/work-items/RE-001-key-value-lookup-115/verify.py` prints
  ALL CHECKS PASSED (digest, provenance, manifest, excerpt
  regeneration byte-for-byte from a fresh objdump run, every
  excerpt instruction byte-for-byte against the raw binary, FDE
  ranges, census, semantic records, model tests).
- Anti-low-quality self-check: three instructions picked from
  the two routines (`0x5d8cf88`, `0x5d8d010`, `0x5d8cec8`)
  verified byte-for-byte against a fresh objdump run and the raw
  binary inside `verify.py`.
- Model: `tools/key_value_lookup_115.py` with
  `tests/test_key_value_lookup_115.py` — 33 checks pass (small
  and hash paths, empty keys, segment-end stops, both value
  paths, end-to-end key-to-value runs, threshold at count 20,
  missing-field and degenerate-bucket guards).

## Environment limits, stated honestly

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
the model is Python only and no Rust reconstruction is claimed.
The full `make verify` suite is not run here: its baseline
already fails on missing LFS material, which is pre-existing
and unrelated to this change. The packet's own checker and the
model tests above are the verification for this work item.
