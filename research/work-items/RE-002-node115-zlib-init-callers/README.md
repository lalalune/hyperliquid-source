# RE-002: qualify the zlib and bzip2 initializer handoffs in node #115

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Baseline 2da45cb0a761cff6b478e40421699857d87a94df. All coordinates are link-time ELF VAs. Function attribution comes from the registered native byte windows. No external source used.

The [inflate linkage packet](../RE-002-node115-native-zlib-inflate-linkage/README.md) traces calls leaving registered zlib bodies. This packet checks the calling ABI at two selected sites entering the initializers. The paired callers pass zlib window bits −14, a pointer to the NUL-terminated literal `1.3.1`, and stream size 112 to `inflateInit2_`. Both immediately test the return register and branch on a nonzero return. Nearby bzip2 entry calls instead clear both scalar arguments before calling `BZ2_bzDecompressInit`. The bzip2 sites use opposite branch polarities but both route zero to their success continuation.

GNU objdump 2.42 in Intel syntax was used to check the surrounding instructions. The offline verifier checks the exact argument-producing instructions, literal bytes, direct displacements, and selected return branches. Its shifted-call controls reject a changed target. This establishes the selected inbound ABI contract for a compatible link. It does not establish the enclosing callers' source identities, exhaust all inbound sites, execute either codec, or change a progress gate.

Run `python3 research/work-items/RE-002-node115-zlib-init-callers/verify.py` from the repository root. The retained output is offline-log.txt.
