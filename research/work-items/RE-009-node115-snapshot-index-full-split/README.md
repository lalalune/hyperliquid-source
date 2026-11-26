# RE-009: selected snapshot full-index split

The nonfull insertion in [#7131](https://github.com/lalalune/hyperliquid-source/pull/7131) excludes full nodes. This packet examines the adjacent path in `0x1ca6180` for a node with exactly 11 existing keys and a valid insertion position `i` in `0..=11`. The code chooses the existing key/value pair to separate and which resulting node receives the new pair:

| insertion position | selected old pivot | insertion side | local insertion position |
| --- | --- | --- | --- |
| `i < 5` | 4 | old node | `i` |
| `i == 5` | 5 | old node | 5 |
| `i == 6` | 5 | new node | 0 |
| `i >= 7` | 6 | new node | `i-7` |

After allocating a `0x430`-byte new node and checking failure, the code preserves the pivot's 24-byte key and 72-byte value, sets new count to `11-pivot-1`, copies the existing suffix after the pivot to the new node, and sets the old count to `pivot`. The two suffix copies use the slot dynamically relocated to `memcpy@GLIBC_2.14`; the following branch selects old or new node for insertion. This is the local split before that insertion and subsequent propagation; parent/root updates and allocation failure handling beyond the branch are outside this packet.

The path assumes valid buffers, normal relocations, no concurrent mutation, the selected caller and a count exactly 11. No key semantics, actual checkpoint or state-root equivalence is claimed. Target Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. `verify.py` checks digest, instruction spans, relocation, mutation controls and all twelve position-table cases; the latter are a model, not execution of captured code. Disassembly and actual static results are included.
