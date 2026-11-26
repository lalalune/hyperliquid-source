# RE-009: snapshot key formatter callback order

The two argument records identified in #7139 reach the shared formatter with descriptor 0x433517. The selected descriptor is exactly C0 C0 00. The argument block is aligned on the caller's stack, so the low pointer bit is clear. In the entry at 0x141e3a0, passing both initial argument tokens with zero literal bytes selects the zero initial reserve path. The output starts as the three words (0, 1, 0).

The relocation for slot 0x64df6f0 binds the formatting call to 0x1680500. In the even-pointer path, C0 uses the current argument index times 16 to load the data pointer and callback. A successful callback increments the index by one and resumes at the next descriptor byte. Thus the selected descriptor calls the marker callback first and the decimal callback second, with no literal separator, and terminates at 00. A nonzero callback return takes the failure branch without advancing to the next argument. This establishes invocation order under normal return, not a measured native output or complete allocation behavior.

The verifier checks the #115 ELF digest, the exact selected descriptor, relocation and instruction windows. Its in-memory corruption controls cover descriptor, relocation and callback-loop changes. All addresses are ELF virtual addresses.
