# RE-009: snapshot mode-1 rmp writer input

The exact-mode-1 output helper selected in the merged snapshot-selection packet configures the rmp serializer differently from the other helper described in #7147. After its extension comparison succeeds, it initializes three writer words to (0,1,0), and passes independent pointers to a result, writer and worker input to 0x2299e60. Result word 0x8000000000000004 rejoins the shared submission path with three independently reloaded output buffer words; other result words go to a separate path. The packet identifies the mode-specific serializer boundary and its input and output layout. It does not establish an exact wire format.

The packet uses ELF virtual addresses and the pinned #115 digest listed in the offline log. Run python3 research/work-items/RE-009-node115-snapshot-mode1-rmp-writer/verify.py from the repository root. The verifier checks relative edges and independent instruction anchors and rejects a mutation to each.
