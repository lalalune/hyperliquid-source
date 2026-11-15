# RE-068: node115 EMA short c37

Static evidence packet for the node115 FDE `[0x4d3b7c0, 0x4d3bb11)` (849 bytes), FDE VA `0xf17298`.

The range implements a tagged comparator: it normalizes signed values, compares tag-dependent payloads, and then walks several length/pointer fields through the shared indirect comparator before a common signed-result path. This packet records only captured bytes, disassembly partitioning, and unwind ownership; no native execution or equivalence claim is made.
