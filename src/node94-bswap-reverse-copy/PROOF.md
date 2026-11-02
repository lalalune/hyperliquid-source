# Ordered copy relation, including overlap

This proof concerns node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, complete
ELF VA range `[0x5632d90,0x5632dbb)`. Its 43 bytes contain four consecutive
load/BSWAP/store groups and one return, with no call, branch, constant table or
runtime helper. The prior foundation packet establishes only a disjoint
source-snapshot formula. This contribution implements the ordered operation
for every valid relative byte offset, including partial overlap and self-copy.

## Instruction relation

| Group | Source load | BSWAP | Destination store |
| --- | --- | --- | --- |
| 0 | `0x5632d90`: `[RSI+24]` | `0x5632d94` | `0x5632d97`: `[RDI]` |
| 1 | `0x5632d9a`: `[RSI+16]` | `0x5632d9e` | `0x5632da1`: `[RDI+8]` |
| 2 | `0x5632da5`: `[RSI+8]` | `0x5632da9` | `0x5632dac`: `[RDI+16]` |
| 3 | `0x5632db0`: `[RSI]` | `0x5632db3` | `0x5632db6`: `[RDI+24]` |

Every load and store is 64-bit. A group loads all eight bytes before its store.
The return at `0x5632dba` preserves the last swapped qword in RAX. There is no
snapshot of all 32 source bytes. Source and destination are not declared
nonaliasing by these instructions.

Let `S` and `D` be logical offsets in a single buffer. Group `t` reads the
current eight bytes starting at `S+24-8t`. If those bytes are `b[0..7]`, their
little-endian qword is `sum(b[k]*256^k)`. BSWAP makes the value
`sum(b[k]*256^(7-k))`, whose little-endian store writes `b[7..0]` at `D+8t`.
The Rust `[u8;8]` snapshot, `from_le_bytes`, `swap_bytes` and `to_le_bytes`
implement exactly this relation without depending on native host endianness.
Induction over four groups establishes equality of the complete buffer and
RAX after each group. No byte outside `[D,D+32)` is written.

For example, disjoint source bytes 0..31 produce destination bytes 31..0 and
RAX `0x0001020304050607`. For self-copy, groups 0 and 1 overwrite the bytes
that groups 3 and 2 later read. The final buffer is 31..16 followed by 16..31,
and RAX is `0x1f1e1d1c1b1a1918`. A single whole-source snapshot, a bytewise
interleaved read/write, or reversing group execution can therefore be wrong.

## Domain and totality

Both logical offsets must convert to usize and satisfy checked `offset+32 <=
memory.len()`. The API checks both regions before any write. The new `Bounds`
result is an API refusal, not a target return or a model of partial native
fault effects. On valid inputs it exposes the raw final register value only;
original application meaning and source-language return type remain unknown.

The target relation assumes corresponding valid, nonwrapping readable source
and writable destination regions in ordinary memory permitting unaligned
qword accesses. Arbitrary byte-offset overlap is admitted. Concurrent changes,
MMIO, address wrapping and native faults are excluded. No pointer is formed
or dereferenced from a supplied u64 by Rust.

For `t` in 0..3, source offsets lie between `S` and `S+24`; each 8-byte region
ends at most at `S+32`. Destination groups are disjoint ranges covering exactly
`[D,D+32)`. The checked premises imply every sum and slice index in the Rust
body is in range and cannot overflow. The multiplication `8t` is at most 24;
`S+24-8t` cannot underflow. The loop always executes four times, and its final
value is initialized and overwritten by the fourth group. The component uses
no allocation, unsafe code, or unbounded traversal.

## Independent backward-provenance oracle

The oracle was frozen before the Rust source existed. It never mutates a
working memory image. Define `origin(a,b)` as the original byte address seen
at address `a` before group `b`. If `a` is not a destination byte written by
an earlier group, `origin(a,b)=a`. Otherwise uniquely write
`a=D+8t+k`, with `0<=k<8` and `t<b`, and define

`origin(a,b) = origin(S+31-8t-k, t)`.

The stage strictly decreases at every recursive step, so this definition is
finite even for self-overlap. Final memory byte `a` is original memory at
`origin(a,4)`. The returned qword is the big-endian interpretation of original
bytes at `origin(S+j,3)`, for `j=0..7`, because the last qword is read before
group 3's store. This is a backward dependency calculation, independent of
the forward Rust qword mutation loop. It handles every byte-value assignment:
all outputs select original bytes, with no data-dependent branch.

Fixtures include every overlapping displacement -31..31 and adjacent disjoint
boundaries -40..40, all eight byte alignments, guard bytes and exact bounds.
The 16,128 source bit-basis cases distinguish byte-origin maps for every
overlap displacement. Seeded additional data tests arbitrary byte patterns
and larger buffers. Bounds cases test empty/short buffers and large u64 offsets,
including values whose +32 would overflow. They verify only the new refusal
policy; successful cases support the target relation.

Native tests execute only newly compiled Rust through an input-only client.
A target identity, full-body/FDE/CIE and both full caller bodies are separately
rechecked. Compiled controls change whole-source snapshotting, intra-qword
load/store order, group order, source/destination order, byte width and RAX.
Those observed mismatches supplement this proof; they are not captured-target
execution or an x86 compiled-byte equivalence claim.
