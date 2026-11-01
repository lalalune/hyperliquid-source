# Frozen input and expected-output protocol

`fixtures/cases.jsonl.gz` retains the human-readable value inputs. These are
independently authored test values, not a private/live dataset or a native wire
format. `fixtures/vectors.tsv.gz` has four tab-separated columns, without a
header: case name, input frame hex, expected preimage hex, expected digest hex.
The eventual own Rust driver receives **only the input-frame hex**, one line per
case. Expectations and case names must not be passed to the implementation.

The input frame is a task-local fixed-width protocol; it is not the target's
variable-width serializer. All words/counts below are little endian. Addresses
and hashes are fixed byte strings. All data must be consumed; trailing or short
frames are invalid driver inputs. Count fields are u32 only for this finite test
transport; this does not introduce a u32 bound on native or public API counts.

| Variant | Input fields, in order |
| --- | --- |
| 2 | byte2, signer20, round:u64, QC version:u64, QC start:u64, QC round:u64, hash32, count:u32, then each vote signer20 and signature72 |
| 3 | byte3, signer20, round:u64, random:u32, snapshot-present:u8, optional snapshot body, optional peer-map body |
| 4 | byte4, signer20, random:u32, round:u64 |

An optional map body is presence:u8, then on1 count:u32 followed by exactly that
many address20/value:u64 pairs. An optional set is presence:u8, then on1
count:u32 followed by address20 entries. Presence must be0 or1. Input order is
preserved, including deliberately unsorted rows; the API does not silently sort
or deduplicate. Native correspondence requires the supplied ordered sequence to
match the finite native tree's in-order projection under `PROOF.md` premises.

A snapshot body is: optional stakes map, optional jailed set, evm-word:u64,
triple-present:u8, then on1 exactly three records of hash32, first:u64, second:u64.
The first two words of each summary precede its hash in the **expected native
preimage**, intentionally differing from this input frame's order.

Signature72 carries eight little-endian u64 limbs in bytes0..63, one unrestricted
final byte64, and seven inactive padding bytes65..71. The expected preimage
encodes each limb with the target scalar varint then appends byte64; it ignores
the padding. This is a memory projection, not an assertion about canonical ECDSA
signatures, recovery ID validity, scalar values or cryptographic verification.

Expected digests are the existing MIT pure-Python standard Keccak helper applied
to independently derived preimages. `corpus.py` extracts only that arithmetic
function and constants with the whole provider hash pinned; it does not import
or run the provider's captured-instruction evaluator. Native permutation identity
remains conditional on the credited structural evidence. No target digest was
executed. An independent size equation checks every fixture's byte length.

The 534 cases cover all scalar width boundaries; each of eight signature limb
positions; mixed limb widths and unrestricted final bytes; seven-byte padding
invariance; counts0/1/2/3/10/250/251; vote ordering and duplicates; all heartbeat
option combinations; absent versus present-empty collections; collection order
and counts through251; all three summary slots and both words; and exact preimage
lengths135/136/137,271/272/273,407/408/409. Odd rate-neighbor lengths unavailable
in the small timeout-only subdomain are supplied by heartbeat fixtures. The
fixtures make no claim that every integer length in the reported bounds occurs.
