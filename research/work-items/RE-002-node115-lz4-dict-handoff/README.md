# RE-002: bind optional LZ4 dictionary arguments at the native stream caller

Target Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. Baseline 2da45cb0a761cff6b478e40421699857d87a94df. Addresses are ELF VAs. Native helper labels come from the byte-window registry.

In the two selected caller blocks, a qword from the dictionary record at offset 0x38 decides whether to install a dictionary. Both installation paths read the pointer at offset 0x30 and call the native LZ4 setter at 0x62ed7f0. The empty branch skips the setter. The setter paths rejoin before the calls to LZ4_decompress_safe_continue at 0x62ed820. This binds the concrete argument record and optional setup to the selected native entry points. The packet does not identify the dictionary record's source type or establish runtime decompression equivalence.

GNU objdump 2.42 in Intel syntax was used to read the selected instructions. Run `python3 research/work-items/RE-002-node115-lz4-dict-handoff/verify.py` from the root. The retained run checks both call pairs and their branch encodings. A shifted displacement in each setter call fails target checking. No captured code is executed and no gate changes.
