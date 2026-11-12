# Node #115 tracker prefix: 20-byte key collection and small sort

Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. These are conditional static observations, not runtime equivalence.

On the selected found-record path, `0x5377502..0x5377543` builds an iterator descriptor and calls `0x5349140`. This helper copies the descriptor and calls `0x5b7b900`, which on its flat iterator variant advances 96 bytes per source row, copies the first 16 bytes plus the next 4 into a separately allocated 20-byte-stride vector, and repeats until the iterator is exhausted. The iterator's tree variant and allocation/growth failures are not covered here.

For a returned vector of 2 through 20 entries, `0x5349271..0x5349282` calls `0x53e5830`, which compares 20 bytes via the ELF import slot `0x64dfb50` (`memcmp@GLIBC_2.2.5`), and shifts preceding 20-byte elements only while the comparison is negative. Subject to a valid nonaliasing buffer and ordinary imported comparison behavior, this is stable ascending bytewise insertion sort. A one-entry vector bypasses sorting; 21 or more use a different indirect path. `0x53491b1..0x534922e` then allocates a node and passes the vector to `0x4ca9730`; its downstream semantics are not established here.

The 20 bytes are not identified as addresses or assigned a protocol meaning. The flat-row reachability, comparator runtime binding, large-input sort, and final output uniqueness remain open. Run `python3 research/work-items/RE-017-node115-tracker-inner-key-build/verify.py` for target authentication and anchored byte/call checks with mutation controls. `windows.txt` contains disassembly and the pinned import relocation.
