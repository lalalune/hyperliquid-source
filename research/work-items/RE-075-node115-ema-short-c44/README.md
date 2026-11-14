# RE-075: node115 EMA short c44

Static evidence packet for FDE `[0x4d3cd70, 0x4d3cf3a)` (458 bytes), FDE VA `0xf17568`.

The helper compares an initial pair, normalizes a tagged `+0x68` field, then walks pointer/length groups at `+0x70`, `+0x78`, and `+0x88/+0x90` through the shared indirect comparator. This is static evidence only; no captured code is executed or emulated.
