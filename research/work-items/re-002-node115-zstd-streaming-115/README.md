# RE-002 · Node #115 RocksDB ZSTD streaming compress/uncompress wrappers

Component: storage / compression. Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Bounded question

How do node #115's RocksDB ZSTD streaming wrappers work: the two `Create`
factories, the `Compress`/`Uncompress` streaming calls, and the two `Reset`s?
Six functions, `0x61c1a20..0x61c1d5a`, all with census records and all body
hashes matching exactly (see `functions.tsv`).

## Answer (pinned)

**Factories.** `StreamingCompress::Create` (`0x61c1c10`, 184 B) and
`StreamingUncompress::Create` (`0x61c1ce0`, 122 B) return `nullptr` for any
compression type other than 7 (`kZSTD`). There is no
`ZSTD_Streaming_Supported()` call in either binary body: the source's check
folds away with `ZSTD_STREAMING` defined. The compress factory allocates a
`0x70`-byte holder: vtable `0x64d7418` at `+0x00`, kind byte 7 at `+0x08`,
the 48-byte options blob copied opaquely to `+0x10..+0x40`,
`compress_format_version` (u32) at `+0x40`, `max_output_len` at `+0x48`, a
fresh `ZSTD_CCtx` at `+0x50`, and the input buffer zeroed at `+0x58..+0x70`;
it then calls `ZSTD_CCtx_setParameter(cctx, 201, 1)` — parameter 201 is the
boolean `checksumFlag` arm, so every frame this object emits carries a
content checksum — and ignores the return value. The uncompress factory
allocates a `0x38`-byte holder: vtable `0x64d7448` at `+0x00`, kind byte 7
at `+0x08`, format version at `+0x0c`, `max_output_len` at `+0x10`, a fresh
`ZSTD_DCtx` at `+0x18`, input buffer zeroed at `+0x20..+0x38`; no parameter
is set. Each factory has exactly one direct caller: the compress factory
from `0x5f0430b` (format version 2, `max_output_len` `0x7ff5`/`0x7ff9`, product
installed at owner `+0x48`), the uncompress factory from `0x5f01e9d`
(format version 2, `max_output_len` `0x8000`, product installed at holder
`+0x78` beside a fresh `0x8000`-byte array). Both callers agree with the
merged cache packets' notes.

**Compress** (`0x61c1b30`, 190 B) and **Uncompress** (`0x61c1a80`, 174 B) are
vtable-only (slot 2 in `0x64d7418` / `0x64d7448`): zero direct calls, tail
jumps or LEA references in the whole `.text`. Both start with
`*output_pos = 0` and return 0 for empty input without touching the engine.
Compress restocks its input buffer only when the stored pointer is null or
differs from the new input pointer; the *same* pointer keeps the stored size
*and* position, so a same-pointer call with a new size still compresses the
old size's worth of bytes (verified by test). Uncompress is the mirror
opposite: any non-null input *replaces* the buffer unconditionally (same
pointer included, position reset, size re-read); a null input keeps the
stored buffer, which is the documented continuation after a full output
buffer. Both call the streaming engine with `endOp = 2` (`ZSTD_e_end`) for
compress / plain `ZSTD_decompressStream` for uncompress, using
`max_output_len_` as the output-buffer size. On an engine error both call
their `Reset` and return −1. On success Compress returns `(int)remaining`
and Uncompress returns `(int)(in.size − in.pos)`. One more Uncompress
quirk, verified against the engine: a *mid-frame* re-pass corrupts the
stream — the buffer is replaced without resetting the DCtx, so the engine
drains its internal buffer and then errors on the restarted frame-header
bytes (Reset + −1). A re-pass is a clean restart only at a frame boundary,
after the previous frame was fully consumed.

**Resets** (`0x61c1a20` / `0x61c1a50`, 40 B each) call
`ZSTD_CCtx_reset` / `ZSTD_DCtx_reset` with directive 1
(`ZSTD_reset_session_only`) and zero the stored input buffer. Each has
exactly one direct caller: its own function's error path.

## What the model does and does not claim

`tools/zstd_streaming115.py` reconstructs the *wrapper*: object layout,
the Create gate and field init, the buffer refresh rules, the early
returns, the error path and the return arithmetic. The ZSTD streaming
engine is the linked dependency (the target statically links zstd 1.5.7);
the tool drives the same public API through the system `libzstd.so.1`
(1.5.5) via ctypes. **Frame bytes are not claimed byte-identical** to the
target's output. What is claimed: the wrapper behaviour, frame validity
(magic, checksum-flag bit, one-shot decode back to the input), and the
2,400 deterministic cases in `cases.tsv` (400 create, 400 reset, 800
compress, 800 uncompress), all byte-checked on decompressed output,
returns and state transitions. `cases.tsv` records only version-stable
outcomes for that reason.

The engine callees are pinned by shape or by the catalogue/merged packets:
`ZSTD_isError` `0x620dd60` (verified: `cmp rdi, -0x78; seta`),
`ZSTD_CCtx_reset` `0x6219c20` (directive dispatch 1/2/3),
`ZSTD_compressStream2` `0x6219dc0` (buffer/endOp checks),
`ZSTD_createCCtx` `0x6218920` and `ZSTD_CCtx_setParameter` `0x6212010`
(merged `RE-001-zstd-compress-cache-115`), `ZSTD_createDCtx` `0x628c0b0`,
`ZSTD_DCtx_reset` `0x628df00`, `ZSTD_decompressStream` `0x628dfd0`
(catalogue labels). Full semantic records are in `records.json`;
instruction-level detail lives only in the verbatim whole-function
excerpts (`*.objdump.txt`) and raw bytes (`*.hex`).

## Unknowns (kept separate)

- The 48-byte `CompressionOptions` layout: the factory copies it opaquely
  and consumes no field, so no field boundary is pinned here.
- The two destructors (which free the CCtx/DCtx) are separate FDEs and are
  not reconstructed in this packet; the tool's `close()` is the Python-side
  analogue, not a binary claim.
- The enclosing functions of the two factory callers are not identified
  beyond their observed argument setup.
- The system libzstd used as the engine oracle is 1.5.5; the target links
  1.5.7.

## Reproduction

Run from the repository root with the node artifact materialized:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
python3 -m unittest tests.test_zstd_streaming115 -v
python3 tools/zstd_streaming115.py --write-cases /tmp/cases-check.tsv
diff research/work-items/re-002-node115-zstd-streaming-115/cases.tsv /tmp/cases-check.tsv
python3 research/work-items/re-002-node115-zstd-streaming-115/census.py --out /tmp/census-check
python3 research/work-items/re-002-node115-zstd-streaming-115/export_excerpts.py
python3 tools/verify_packets.py
```

The local run used Python 3.12.14, Capstone 5.0.7 and pyelftools, GNU
objdump 2.42, and system libzstd 1.5.5. The artifact was read only; the
target binary was never executed. Upstream base commit: `0781ce048`.
