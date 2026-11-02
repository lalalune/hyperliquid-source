# Node94 stateful hexadecimal-pair iterator

This independently authored, dependency-free `no_std` Rust implements the
complete constructed valid-string relation of node94 ELF VA
`0x4eb64f0..0x4eb68a9` (953 bytes), including the normal Unicode error-scalar
dependency at `0x4eb6360..0x4eb63ec` (140 bytes). The two code denominators stay
separate. It does not implement the enclosing address parser.

`HexPairs::new(&str)` starts cursor/count/halt at zero. The input is immutable;
native state/output/string roles must remain separated. Original pointers,
nominal structs/enums, calling ABI and forged states are not implemented.

`next_into(&mut [u8;16])` returns the same supplied output reference. It skips
exactly ASCII tab, LF, CR and space before each hex nibble, accepts ASCII
0..9/A..F/a..f, and combines a pair. It removes no prefix: `0x` yields an
invalid `x` at index one. Unicode whitespace is invalid as well.

- Tag2 writes a little-endian u32 at bytes0..4 and the decoded byte at4.
  Bytes5..16 retain their previous contents.
- Tag3 (natural end or a later halted call) writes only bytes0..4. Natural
  exhaustion can keep halt false.
- Tag1 (one nibble without another, possibly after whitespace) writes only
  bytes0..4 and sets halt true.
- Tag0 writes all 16 bytes: u32 tag, u32 invalid Unicode scalar, u64 original
  byte index. It sets halt true. The outer cursor/count consume only that
  scalar's first byte; a distinct native helper decodes its complete scalar.
  The next halted call avoids the now potentially interior UTF-8 cursor.

All multi-byte writes are little-endian. Cursor, consumed count and halt are
available as logical observations. Reuse the output to observe exact stale
payload preservation. No allocation, I/O, registry dependency, original-byte
transplantation or target execution is involved in the production library.

The independent full-path proof establishes the active invariant: prior
consumed bytes are ASCII, cursor equals start plus count, and count is bounded
by valid string length. That proves the three native overflow/slicing/missing-
scalar panic branches unreachable in this domain. Invalid UTF-8, externally
mutated/forged state, faults, unwind and physical access timing remain outside
the bridge. The scalar helper's positional UTF-8 equations are separately
closed; its source or nominal type is not assumed.

Accepted #339 binds outer ASCII address framing and selected iterator anchors.
Merged #1334 implements the outer ASCII 20-byte acceptance projection and
explicitly leaves Unicode, complete iterator state and helper closure open.
This component supplies that distinct missing stateful operation, while their
source and scope remain unchanged.

Build with the authenticated research Rust 1.94.1 provider, directly with
rustc. There is no inferred original Cargo manifest, workspace or lockfile:

```sh
/path/to/verified/rustc --edition=2021 --crate-name node94_hex_pair_iterator \
  --crate-type=rlib -D warnings -C overflow-checks=on -C opt-level=3 \
  src/node94-hex-pair-iterator/lib.rs -o /tmp/libnode94_hex_pair_iterator.rlib
python3 -B tools/hex_pair_iterator_rust.py --rustc /path/to/verified/rustc \
  --output /tmp/fresh-hex-pair-build --controls
```

The runner pins the recorded provider's 103 payloads and original installation
manifests, including its scratch prefix; see the evidence packet for exact
replay requirements. The input-only external driver reads raw UTF-8 bytes,
initial 16 output bytes and call counts, then prints every actual full output,
cursor/count/halt and same-output identity. It receives no expected answer.
The independent oracle was frozen before this source. Actual build/control
results belong to the [evidence packet](../../research/work-items/RE-001-hex-pair-iterator-94/README.md).
