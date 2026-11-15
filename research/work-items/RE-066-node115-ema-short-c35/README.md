# RE-066: node115 EMA short c35

Static evidence packet for the pinned node115 FDE `[0x4d3b4d0, 0x4d3b5b1)` (225 bytes), FDE VA `0xf17230`.

The range contains four repeated pairwise scalar-comparison groups. Each group loads two 16-byte-spaced records, computes an unsigned subtraction with `cmovb`, calls the same indirect comparator slot, and exits early on a non-zero comparison. The final group returns the signed comparison result via `set*` plus `sub al,cl`. This packet records bytes and unwind ownership only; it does not claim native execution, ABI equivalence, or helper implementation.

The captured artifact is authenticated by SHA-256 and every semantic witness is checked against the ELF bytes. The verifier also rejects truncated/modified captures and a mutated anchor byte.
