# RE-002 · Node #115 RocksDB ZSTD streaming engine methods

Component: storage / compression / streaming. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Bounded question

How does node #115 drive its ZSTD streaming engine -- what do the two
`Reset` methods reset, how do `Compress` and `Uncompress` stream bytes
through the engine, what do they return, and who calls them? The four
functions are all census-bound (body hash matches the vendor census
`target_body_sha256` exactly; source hash reproduced by zeroing the
recorded relocations):

| function | FDE | size | body SHA-256 |
|---|---|---|---|
| `rocksdb::ZSTDStreamingCompress::Reset` | 0x61c1a20..0x61c1a48 | 40 | `d5ffa8536d721ffedcc7131535d0f7f2c22b7642a4d970625ccd7c92e6babb3e` |
| `rocksdb::ZSTDStreamingUncompress::Reset` | 0x61c1a50..0x61c1a78 | 40 | `82ed83a32a2ae24aa44eb29f5c06054be5c8eb07b6b279c57bb1f7557fe595ee` |
| `rocksdb::ZSTDStreamingUncompress::Uncompress` | 0x61c1a80..0x61c1b2e | 174 | `2e18c310ed1a341aa929f49457f21254d6c08673b56f08f325206464f325cc61` |
| `rocksdb::ZSTDStreamingCompress::Compress` | 0x61c1b30..0x61c1bee | 190 | `f7db8e9f5ecefdeb34b40cfb69b64696073c0b4bbb7510dda585eb1ddf55cfc2` |

Scope note: the run first aimed at six functions including the two
`Create` factories (0x61c1c10 / 0x61c1ce0), but duplicate-checking found
both already reconstructed -- 0x61c1c10 in full in merged
RE-001-zstd-compress-cache-115, 0x61c1ce0 in merged
RE-001-zstd-decompress-cache-115 (PR #3635). This packet covers only the
four engine methods; the factories' bodies, the options template values
and the landing-pad tails are cited from those packets, not re-claimed.

## Answer (pinned)

**Holders.** Compress holder 0x70 bytes: vptr +0x00, `CompressionType`
+0x08 (1 byte, 7 = kZSTDCompression), `CompressionOptions` +0x10..+0x40
(48 bytes, copied verbatim by the factory),
`compression_format_version_` u32 +0x40 (2 in both Create callers),
`max_output_len_` size_t +0x48 (0x7ff5/0x7ff9 from the Writer),
`cctx_` +0x50, `inBuffer` +0x58..+0x70 (src +0x58, size +0x60, pos
+0x68). Uncompress holder 0x38 bytes: vptr +0x00, type +0x08,
`compression_format_version_` u32 +0x0c (2),
`max_output_len_` size_t +0x10 (0x8000 from the Reader),
`dctx_` +0x18, `inBuffer` +0x20..+0x38 (src +0x20, size +0x28, pos
+0x30). Layouts from the merged factory packets, re-verified here
through the methods' field accesses.

**Reset (both classes, 40 B each).** Call the engine reset on the
context slot with directive 1 (`ZSTD_reset_session_only`) --
`ZSTD_CCtx_reset` on `[this+0x50]` (call at 0x61c1a31),
`ZSTD_DCtx_reset` on `[this+0x18]` (call at 0x61c1a61) -- then zero
the whole 24-byte `inBuffer` struct (src/size/pos). Returns void. No
null check precedes the engine call. The `ZSTD_DCtx_reset` callee
(0x628df00) is census-confirmed; `ZSTD_CCtx_reset` (0x6219c20) is
identified by shape + role + twin (it decodes the directive with `and
$~2` and clears the flag at CCtx+0xe18, the same flag the merged
`setParameter` reconstruction gates on).

**Compress (190 B).** Signature `int Compress(const char* input, size_t
input_len, char* output, size_t* output_len)`. `*output_len = 0` first;
`input_len == 0` returns 0 at once. Resume rule on the member
`inBuffer`: if `inBuffer.src` is null OR differs from the input
pointer, store `(input, input_len, pos 0)`; if it is the SAME pointer,
keep `(src, size, pos)` and resume from the saved pos. Then
`ZSTD_compressStream2(cctx_, &out, &inBuffer_, endOp 2 = ZSTD_e_end)`
(call at 0x61c1ba2) with `out = {dst: output, size: max_output_len,
pos: 0}` on the stack. If `ZSTD_isError(ret)` (call at 0x61c1bad):
`Reset()` (call at 0x61c1bdd) and return -1. Otherwise `*output_len =
out.pos` and return `(int)ret` -- the remaining bytes to flush (0 =
frame complete).

**Uncompress (174 B).** Signature `int Uncompress(const char* input,
size_t input_len, char* output, size_t* output_len)`.
`*output_len = 0` first; `input_len == 0` returns 0 at once. If `input
!= nullptr`, store `(input, input_len, pos 0)` into the member
`inBuffer`; a null input keeps the previous buffer and resumes from
its saved pos -- a different rule from Compress, which keys on pointer
equality. Then `ZSTD_decompressStream(dctx_, &out, &inBuffer_)` (call
at 0x61c1ae2) with `out = {dst: output, size: max_output_len, pos: 0}`
on the stack. If `ZSTD_isError(ret)` (call at 0x61c1aea): `Reset()`
(call at 0x61c1b1d) and return -1. Otherwise `*output_len = out.pos`
and return `(int)(inBuffer.size - inBuffer.pos)` -- the input bytes
still unconsumed (low 32 bits).

**Findings (verified live against the system engine).**

- *Mid-frame input switch (Compress):* switching the input pointer
  while a frame is still flushing does NOT feed the new bytes into the
  open frame -- the engine ignores them until the frame flushes. The
  finished frame holds the consumed prefix of A plus only the bytes of
  B consumed during the flush (0 in every tested case); the pending
  remainder of B starts a NEW frame on the next call, which round-trips
  to exactly that remainder. The caller contract is therefore: keep
  passing the same input pointer until Compress returns 0, then switch.
- *Raw-block consumption (Uncompress):* for incompressible (raw)
  blocks the engine consumes the whole supplied prefix at once and
  buffers the decoded output internally, so the return (input
  remaining) can be 0 while output is still pending; for compressed
  blocks the return tracks decoding progress. Both follow the same
  binary rule (`inBuffer.size - inBuffer.pos`).
- *Frame-completion latch (Uncompress):* `ZSTD_decompressStream`
  returns 0 only on the call that finishes the frame; later no-op calls
  report a nonzero hint (9, waiting for the next frame). Completion is
  a latched event, not a stable return value.
- *`ZSTD_isError` threshold:* strictly greater than `(size_t)-120` --
  the callee body is `xor eax,eax; cmp $0xFFFFFFFFFFFFFF88,%rdi; seta
  %al; ret`. Code 2^64-120 is NOT an error; 2^64-119 is.
- *Options are inert for the engine:* Create applies only the checksum
  flag (`ZSTD_CCtx_setParameter(cctx, 201, 1)`) to the fresh CCtx, so
  the CCtx runs at its default level (3). The 48-byte options copy is
  stored but never read by any of these four methods (nor by the
  destructors).
- *Landing pads:* the tails at 0x61c1bee..0x61c1c03 (delete 0x70) and
  0x61c1cc8..0x61c1cdd (delete 0x38) have their own FDEs and belong to
  the two factories' `new` cleanups, not to Compress/Uncompress.

**Caller census** (whole-.text E8/E9/LEA scan, Capstone-validated,
`census.py`): exactly 2 validated sites. `Reset` (compress) is called
only from Compress's error path (0x61c1bdd); `Reset` (uncompress) only
from Uncompress's error path (0x61c1b1d). Compress and Uncompress have
ZERO direct callers -- they are vtable-only (compress slot 2,
uncompress slot 2; slot 3 is Reset in both tables, per the merged
vtable packets).

**Engine callees.** `ZSTD_DCtx_reset` 0x628df00 and
`ZSTD_decompressStream` 0x628dfd0 are census-confirmed.
`ZSTD_CCtx_reset` 0x6219c20, `ZSTD_compressStream2` 0x6219dc0,
`ZSTD_createCCtx` 0x6218920, `ZSTD_CCtx_setParameter` 0x6212010,
`ZSTD_isError` 0x620dd60 and `ZSTD_createDCtx` 0x628c0b0 have no
census record and are identified by shape + role + twin, cross-checked
against the merged cache packets (see `records.json`).

## Cases

2,400 deterministic cases in `cases.tsv`, generated by
`tools/zstd_stream_methods115.py` (`gen-cases`) and replayed by
`tests/test_zstd_stream_methods115.py` (24 tests pass):

- 600 reset (300 compress + 300 uncompress: fresh, after-partial,
  after-error, double) -- the engine reset runs with directive 1 and
  the inBuffer reads back zeroed.
- 600 compress (200 single-shot round-trips incl. empty, 200
  same-token resumes, 100 new-token restarts, 100 forced-error) --
  frames carry the checksum bit and round-trip through the independent
  direct decompress; the resume and token-switch behaviours above are
  asserted per case.
- 600 uncompress (200 round-trips, 150 null-input resumes, 100
  corrupt-frame errors, 150 split-feed partials) -- the return rule
  and the frame-completion latch are asserted per case.
- 600 bindings (per-function structural checks, relocation
  displacements decoded to the pinned callees, stride-1 16-byte windows
  over each FDE, vtable slots, the isError threshold sweep, layout
  fields, caller sites, callee identifications, factory-caller
  context).

## Environment limits

No cargo/rustc/git-lfs/Ghidra on this VM. The target binary is never
executed. The ZSTD engine calls go through the system libzstd.so.1
(1.5.5) via ctypes on real context handles (the target statically
links zstd 1.5.7; the public API is the same).
`make verify/test/catalogue-check` in a tooled environment is still
owed upstream.

## Unknowns

- Upstream source cross-check for these four bodies (RocksDB v8.1.1
  `util/compression.h`, same header region as the destructors at lines
  1754-1783): NOT completed this cycle -- the browser fetch of that
  file region failed and was not retried. This packet rests on the
  binary + census + the merged packets' upstream confirmations.
- Where the `format_version` field (+0x40 compress / +0x0c
  uncompress, value 2 in both Create callers) is ever read: none of
  these four methods, the destructors, or the factories reads it after
  storing it.
- `ZSTD_CCtx_reset(NULL, 1)` / `ZSTD_DCtx_reset(NULL, 1)` behaviour:
  the binary issues the engine call with no null check, but the
  callee's NULL behaviour is unverified, so the model detects a null
  ctx and records it instead of executing the call. Unreachable on a
  factory-built holder.
- The full field layout of the 48-byte `CompressionOptions` struct:
  only the verbatim copy and the Writer's stack-init values are
  pinned.
- Whether any path other than the factory sets the CCtx compression
  level from the copied options: no such call was found in the factory;
  the Writer/Reader paths were not traced for a later level set.
