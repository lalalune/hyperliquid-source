# RE-002: qualify the node #115 dynamic export hash

Baseline 2da45cb0a761cff6b478e40421699857d87a94df. Linux x86-64 node #115, SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. No external source used.

The loader-facing GNU hash table at VA 0x3ad0 begins at DT_GNU_HASH and ends at DT_STRTAB. Parsing it through PT_LOAD identifies one bloom word and one bucket. Bucket zero selects dynamic symbol 509, the only chain entry. The symbol is defined and its name is `_ZNKSt5ctypeIcE8do_widenEc`. Computing the hash from that name reproduces both bits of the bloom word and the chain word with its termination bit set. This supplies a reference for link output even when section headers are unavailable.

Two name controls clarify the scope. Replacing the final c with e changes the masked chain hash. Replacing it with d preserves that masked hash, so hash agreement alone cannot establish identity and the loader must still compare names. No dynamic lookup or captured target code was executed.

Run `python3 research/work-items/RE-002-node115-gnu-hash/verify.py` from the repository root. See offline-log.txt for the observed results. Linker options and component gates remain unresolved.
