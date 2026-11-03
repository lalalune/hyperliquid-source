# node115 fresh u64-key hash

Independently authored MIT value reconstruction from original instructions and
pre-Rust observations in `research/work-items/RE-014-u64-key-hash-115/`.
`fresh_hash(seed0,seed1,word)` returns the raw u64 from the fresh eight-byte
hash path, including its actual writer CALL/RET and finalization. The word is
stored little-endian by the original wrapper. All arithmetic wraps modulo2^64.

The original entry initializes four seeded words, absorbs the one input word,
absorbs an eight-byte length tag and performs its observed final rounds. This
API is owned value code, not recovered original object/streaming ABI. No Rust
source, constants, tests or address from an unlicensed inferred implementation
is used. ELF-view support and local ROL handler pattern reuse our existing
project-authored MIT research code; the hash itself is independently authored.

From the repository root, using the pinned owned research rustc1.94.1:

```sh
python3 research/work-items/RE-014-u64-key-hash-115/build.py \
 --rustc /path/to/rustc --output work/hash-review
python3 -m unittest discover -s tests -p test_node115_u64_key_hash.py -v
```

Output must be new. The builder authenticates and reinterprets original bytes,
compares all1622 distinct(seed0,seed1,word) triples at opt0/3, repeats its own
opt3 library and compiles seven corruptions against exactly those inputs.
41 actual original rows form one Rust smoke test. No expected answers enter
the input-only client. Research compiler1.94.1/LLVM21.1.8/macOSarm64 does not
establish an original Linux compiler recipe or machine-byte equivalence.

Only the raw returned word is compared. Primary91/91 instruction addresses
are visited; the real writer is56/141 on fresh-length8 inputs. Its other
streaming modes, arbitrary input memory/length, malformed state, stack/flag
side effects, selector lookup behavior and protocol roles remain outside scope.
All component gates stay false; no root Cargo graph or dependency is invented.
