# RE-012: complete node #115 LZ4 forward-match helper in Rust

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`; component transport / RE-012.
Addresses are ELF VAs; no rebasing or byte normalization. Independently authored
MIT Rust and research. The static verifier was adapted from repository-authored
MIT research in [PR2771](https://github.com/lalalune/hyperliquid-source/pull/2771),
head `8ede1e78eb0b18d0faeb5dea619a566b73d4221c`; all new exports and the helper
extent are freshly obtained from the authenticated capture. No unlicensed
inferred source or public LZ4 implementation was consulted or copied.

## Gap and complete selected result

The base has a buildable size-prefixed decoder but no buildable compressor
forward-match helper. The prior static dictionary result records a call target
but does not establish this callee's complete two-input/cursor semantics. This
packet closes the whole helper `0x477e7c0..0x477e941` (385 bytes / 113
instructions), rather than extracting part of an inlined compressor sequence.
`src/node115-lz4-match-extension` is a real dependency-free `no_std` Rust crate.

Two complete compressor FDEs are retained as calling context:
`0x477e950..0x477f036` and `0x477f040..0x477f746`. The three-FDE static
denominator is 3,949 bytes / 922 instructions; repeated caller context does not
supply new byte-coverage credit. GNU2.45 / LLVM23.1.4 / Capstone5.0.7 complete
instruction partitions agree; the repository FDE parser and GNU readelf agree
on all extents. `records.json` retains instructions' branches/calls, FDE/CIE
bytes and actual selected relocation writers.

## Observations, reduction and caller closure

At entry, RDI is the left pointer, RSI its length, RDX a pointer to the mutable
left cursor, RCX the right pointer, R8 its length, and R9 the right cursor.
These are bounded register observations, not an assertion of source function
names or a public native ABI. The complete helper has no normal-path external
calls. Its five calls go only to opaque failure helpers.

1. `0x477e7d1..0x477e7e4` loads the left cursor, computes left length minus
   **six**, then subtracts the cursor; borrow takes a failure-helper edge.
   `0x477e7e4..0x477e7f0` then subtracts right cursor from right length,
   with its own failure edge. No cursor store occurs on either edge.
2. `0x477e7f8..0x477e810` derives the minimum whole-eight-byte count from
   those two remainders. `0x477e820..0x477e83d` compares qwords until a
   mismatch or the whole-word limit.
3. A qword mismatch uses XOR, `tzcnt`, and shift-right-three at
   `0x477e8b7..0x477e8c2`. Because the loads are little endian, this gives
   the first differing byte within the word, not the highest differing bit.
4. Whole-word equality falls through to the minimum remaining tail
   (`0x477e83d..0x477e858`). When no whole word exists, the scalar path
   starts at `0x477e888`; both scalar paths stop at the first unequal byte
   or the smaller remainder.
5. `0x477e8d3..0x477e8e5` adds the equal count, stores the final left
   cursor, and returns the additional count in RAX. The qword-mismatch arm
   reaches the same final store. The right cursor is passed by value.

The two actual calls are at `0x477ebb5` and `0x477f2b5`. Their argument setups
pass the same input pointer/end to both sides, left cursor already advanced by
four, and candidate cursor advanced by four. Thus this helper's return value
excludes the already matched four bytes. The helper itself supports two
separately bounded read-only inputs; equal input cases in the host probe really
reuse the same slice to exercise the actual callers' aliasing shape.

The safe API requires a left length >=6, because the target's initial len-6
instruction wraps below that domain. `SourceShorterThanSix` is an explicit
adapter rejection, not a recovered native failure. Native left/right borrow
edges become logical enum boundaries with an unchanged cursor. Within safe
slice extents, matched <= left_length-6-old_cursor and matched <=
right_length-right_cursor. Therefore subsequent checked additions cannot
carry, and the word/tail reads stay inside both extents. Native overflow
failure helpers, pointer-invalid domains and exact panic payloads remain
outside this API; no synthetic fixture is claimed to reach an impossible
addition-overflow edge.

Five exact Source Location records point to the captured
`z_vendor/lz4_flex/src/block/compress.rs` filename. Raw pointer words are zero
in `.data.rel.ro`; `locations.json` and the verifier resolve each via its
actual symbol-zero RELATIVE writer to `0x44acb4`. This attributes the dependency
source path; it does not identify an exact public lz4_flex revision or prove
an unmodified dependency. An initial VA0 filename-anchor attempt was rejected
by the unique-section check and corrected through those actual writers. The
original failure note is retained under ignored `work/environment/ten-tasks/
match-extension/initial-static-export-failure.txt`.

## Independent qualification and limits

`oracle.py` expresses a Python slice/zip common-prefix relation independently
of the Rust qword/ctz algorithm. It froze **42,050** cases in `cases.tsv`
before the Rust directory existed; `freeze.json` retains the historical false
existence flag and exact hashes. Fixture SHA-256:
`86326c75e19f85a79320547fbf73b59939eaa431e6e060e47beff8b4dec00bb2`.
Cases include short/rejected domains, both cursor boundary orders, unequal
input extents, zero remaining bytes, every differing bit near qword/tail
boundaries, nonzero positions, long equal runs, and aliasing input shape.

Actual debug and release builds each match all 42,050 expectations. Seven
separately compiled production mutants exit normally and mismatch: reserve
five bytes, big-endian qwords, wrong bit-to-byte conversion, skip scalar tail,
wrong cursor update, include the initial four bytes, and ignore right cursor.
Their exact first mismatches/source hashes are in `qualification.json`;
original build/output/stderr files remain under ignored
`work/environment/ten-tasks/match-extension/qualification/`.

Static replay rejects 18 actual anchor corruptions (instruction and data) and
two wrong target identities. Those controls bind evidence, not target runtime
behavior. `validation.json` records build, formatting, clippy and static results.

```
python3 -B research/work-items/RE-012-lz4-match-extension-115/verify.py
python3 -B research/work-items/RE-012-lz4-match-extension-115/qualify.py
cargo +1.95.0 fmt --check --manifest-path src/node115-lz4-match-extension/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-lz4-match-extension/Cargo.toml -- -D warnings
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-lz4-match-extension/Cargo.toml
```

Only independently authored Rust executes on the host; the Linux rlib is built
without running it. No captured execution/emulation, sockets, chain traffic,
original ABI equivalence, whole compressor or byte-equality claim exists.
Initialization, backward extension, dictionary state, literal/token/offset
emission and complete compressor integration remain separate work. All
full-scope gates and compiled-byte totals stay unchanged. The next integration
step is carrying this additional-count/cursor contract into the selected
compressor's complete match-sequence emission.
