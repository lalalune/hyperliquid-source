# Frozen input-only protocol

Each ASCII/LF input line contains an opaque 24-character lowercase hexadecimal
ID, one tab, and a byte string as lowercase hexadecimal. The single marker `-`
means empty bytes. Hex strings must have even length. IDs must be unique within
the stream. Empty streams produce no output. Case labels exist only in
`corpus/provenance.json`, never in a client request.

Each output line is the same ID, a tab, exactly 64 lowercase hexadecimal digest
characters, and LF. There are no banners or diagnostic lines on stdout. The
comparison harness rejects duplicate/missing/reordered IDs, extra/truncated
lines, malformed case/length/hex, altered values, or trailing data. The future
client accepts stdin only, rejects arguments and malformed inputs with nonzero
status and stderr, and buffers all answers before writing stdout so malformed
suffixes cannot yield a successful prefix. These parsing choices are new
qualification protocol policy, not recovered native behavior.

`inputs.tsv.gz` and `expected.tsv.gz` are separate gzip members with deterministic
mtime zero. SHA256 of their decompressed byte streams is recorded separately.
The harness alone reads expectations. The future client consumes only decoded
input bytes and opaque IDs, then calls the existing provider API.

`corpus.py` derives its values from a 64-plane mathematical representation with
coordinate rho/pi and LFSR-generated constants. It never reads existing Rust
source, native disassembly, or native constants for answers. The 2,000 distinct
messages cover all byte values, all lengths 0..407 with zero/ones/patterned
families, lane/byte/bit and rate boundaries, sparse changes, longer blocks,
embedded NUL, ASCII, and 128 deterministic data inputs. Deduplicated semantic
labels remain separately inspectable. All 256 byte-aligned official round3
short-message vectors independently match; non-byte-aligned vectors are outside
the slice contract. These expectations are mathematical outputs, not captured
target output or CPU equivalence evidence.
