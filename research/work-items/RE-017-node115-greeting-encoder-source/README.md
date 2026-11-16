# Greeting payload wire encoder (node115)

This reconstructs the successful typed payload writer selected by
`232b860 -> 2cd6de0`, including every selected child schema. The downstream
consumer is the greeting transport path already established by
[RE-017-abci-greeting](../RE-017-abci-greeting-115/README.md). That packet owns the
snapshot/export, sizing, allocation, serialization wrapper, and send path;
this contribution supplies the previously missing child layout and executable
Rust encoder. It does not reconstruct a second transport or snapshot exporter.

Target: `artifacts/node/115/hl-node`, 105896032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All addresses below are image virtual addresses. Evidence comes from static
bytes, ELF bindings and full FDE transcripts, without target execution or
emulation. The fixtures below are independently generated schema expectations,
not observations of a running node.

## Scope and prior work

The new source is `src/node115-greeting-encoder`. It reuses
`node115-varint-buffer-writer::write_u64` and the public Address/Signature/SigMap
representations from `node115-nested-certificate-decision::sigmap`. These remain
credited prior contracts. It independently binds this caller's `2935e30` writer
to the same selected little-endian compact-u64 bytes; it does not infer a child
schema solely because a prior crate uses similar data.

Current-main search found no Rust implementation of this greeting writer or its
selected children; the existing greeting packet stops at size/write dispatch.
A fresh open/closed PR search is also recorded in the PR description. The task
supports RE-017 peer/state handoff reconstruction, without claiming complete
peer protocol behavior, checkpoint provenance, or end-to-end synchronization.

## Exact wire contract

Let `U(n)` be one byte for 0..250, `fb || LE16(n)` through 65535,
`fc || LE32(n)` through 2^32-1, and `fd || LE64(n)` otherwise. All child calls
set `dl=0`: the endian swap branches in `2935e30` are not selected. The full
primitive is retained, including thresholds and stores. The inner u32 writer
`2935c50` emits discriminants 0, 1 and 2 as single bytes too.

`232b860` dereferences the input's first Arc pointer and writes its payload at
+10. This crate takes that live payload as a typed value, without the Arc ABI.
`2cd6de0` indexes the signed-relative table at `60be64`. For valid outer values,
a nonnegative capacity selects kind0, and raw niche words MIN..MIN+4 select
kinds1..5. The table's six targets are pinned in `records.json`.

| Wire kind | Bytes after the one-byte kind |
| --- | --- |
| 0 | `U(B+10 length)`, blob from `B+8`, `U(B+98)`, inner detail |
| 1 | `U(B+18)`, `U(B+8)`, `U(B+10)` in that order |
| 2, 3, 4, 5 | No payload |

The kind0 detail selector is loaded at `B+18`: the unsigned comparison and
conditional add select 0 for MIN+1, 1 for an ordinary map representation
(including MIN for a tree), and 2 for MIN+3. This is a typed valid-value encoder;
it does not expose a decoder or certify arbitrary niche words as valid values.
The detail bytes follow their one-byte inner tag:

| Inner tag | Bytes |
| --- | --- |
| 0 | 32 bytes `B+50`, signature vector `B+20`, signature vector `B+38`, 32 bytes `B+70` |
| 1 | 32 bytes `B+58`, signature map `B+18`, signature map `B+38`, 32 bytes `B+78` |
| 2 | Pointed object at `B+20`, three fixed parts as below |

Kind0 blob copy is bound to imported `memcpy` at `64df508`. Neither the blob
nor fixed-size fields receive any transformation. `2788120` copies 32 bytes;
`2787fd0` copies 20 bytes without a length prefix.

### Signatures and maps

`232d9e0` prefixes the vector length with U, then advances native rows by 72
bytes. Each signature writer `2cd80f0` loads eight consecutive little-endian
u64 words at offsets 0..38 and writes each with U. It then dereferences the
pointer supplied for the native recovery byte and appends that byte unchanged.
The reused `[u8;65]` stores the eight words in its first 64 bytes and recovery
in byte64; native trailing padding is excluded. Recovery is not a varint and
is not range-checked as a cryptographic recovery ID by this writer.

`2702610` copies its first 32-byte field at C+40 (C=B+18), then selects each
map independently: MIN chooses a tree at C+8 / C+28; an ordinary capacity
chooses a ring at C / C+20. There is no tree/ring wire discriminant.

`2455520` emits tree count then its in-order entries: key at node+320+20*i,
value at node+8+72*i. It descends children at +400, resumes through parent
links and parent index +3fc, and advances one key per emitted entry. The
encoded pair is raw address20 followed by the signature above.

`24e84c0` and `24e8690` emit ring length then the two logical spans from head
to capacity, followed by the wrapped span. Row stride is 96; key at +0,
signature words at +18, recovery byte at +58. Inactive capacity/padding is not
serialized. The source reuses SigMap's ordered entries rather than sorting
again or emitting physical ring storage. Valid geometry, sorted unique map
keys, and stable live inputs are premises; the checked SigMap constructor can
enforce ring geometry/order before use. No mutation/concurrency claim is made.

### Three fixed parts

`2a01300` serializes exactly three parts from an object of size 0x1830. Part i
starts at i*0x810. For each, it writes U(word+800), U(word+808), then the raw
2048 bytes at the part start. There is no part count, byte-array length, or
extra fourth part. It is not a vector and the numeric words precede the byte
array despite following it in memory. Source `FixedPart` names retain these
offsets because their protocol meaning is not established here.

## Validation and limits

`verify.py` checks the target digest/size, 13 full FDE boundaries and complete
transcripts (1625 instructions), 351 selected instruction witnesses, the
memcpy import, and the jump table. Eighteen negative controls reject wrong
target/table, reordered fields, omitted counts, wrong tree/ring selection,
physical ring traversal, signature padding/raw-byte encoding, encoded recovery,
missing/faulty fixed parts, and compact-integer threshold/endian changes.
These controls test evidence consistency, not native execution semantics.

`fixtures.py` independently generates 26 frozen wire expectations from the
field schema, using all compact-integer widths and blob lengths 0/1/250/251.
Rust compares all four map representation pairs and 30 head rotations (every
rotation of capacities 5 and 6), tests all six outer kinds and all three inner
forms, empty maps/vectors, fixed payload order, and all 256 recovery bytes.
The generator's `--check` mode confirms the committed fixture bytes.

```sh
PYTHONPATH=/path/to/capstone-5.0.7-and-pyelftools python3 research/work-items/RE-017-node115-greeting-encoder-source/verify.py --target artifacts/node/115/hl-node
python3 research/work-items/RE-017-node115-greeting-encoder-source/fixtures.py --check
cargo test --manifest-path src/node115-greeting-encoder/Cargo.toml
cargo test --release --manifest-path src/node115-greeting-encoder/Cargo.toml
cargo clippy --manifest-path src/node115-greeting-encoder/Cargo.toml --all-targets -- -D warnings
```

Allocation/refusal paths, invalid raw memory/tags, Arc ownership/destruction,
input decoding, crypto validity, semantic names for these fields, snapshot
provenance, and socket framing remain outside this successful encoding
contract. The returned Error belongs to the reused host varint writer; other
Vec allocations use Rust's ordinary behavior. No native allocation error union
or precise partial-output behavior is claimed. Unit and schema tests do not
close the repository's full component/runtime gate.
