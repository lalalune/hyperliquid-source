# RE-073: node115 EMA short c42

Static evidence packet for FDE `[0x4d3cb30, 0x4d3ccad)` (381 bytes), FDE VA `0xf174f8`.

The range compares a leading `+0x90` field, then walks four repeated length/pointer pairs through the shared indirect comparator with early exits. This packet records static bytes and unwind ownership only; it does not execute or emulate the captured binary.
