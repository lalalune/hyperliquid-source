# RE-002: verify the node #115 Snappy size-to-buffer handoff

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Base 2da45cb0a761cff6b478e40421699857d87a94df. Coordinates are link-time ELF VAs. No third-party source used.

Two direct calls to the registered GetUncompressedLength body at 0x620b5a0 pass a pointer to a stack length. The true branches go to 0x5db1990 and 0x616ca40, which read that length into the second argument register. On the selected path with an allocator object present, both issue the vtable call at offset 0x98 and use its return pointer as the third argument to RawUncompress at 0x620db60. Both then test its Boolean return. This binds the registered Snappy bodies to the actual size and buffer handoff in the target.

The verifier checks the call displacements, branch targets and argument transfer instructions. It rejects one-bit changes to the selected probe branches. The retained log covers two selected paths. Alternate allocation and error handling, runtime behavior and full call coverage are outside this packet. No gate changes.

From the repository root run `python3 research/work-items/RE-002-node115-snappy-sizing/verify.py`. GNU objdump 2.42 was used to read the surrounding code. No captured code is executed.
