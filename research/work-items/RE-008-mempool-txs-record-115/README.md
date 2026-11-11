# RE-008: node #115 line writers (tenth stage): the global extra-flush byte and the mempool_txs record

- Component ID: abci. Question: the ninth stage (open PR #5876) found that the second task spawned by `0x5a81ed0` (poll `0x5a82670`) calls the line write `0x4e3eaa0` once, at `0x5a88864`, with a record at `rsp+0x1420`, and that the write flushes again when the writer flush byte (`+0xaa`) and the global byte `0x64ffe50` are both set. It left open what sets the global byte and how the record is built.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5872, #5874 and #5876. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, FDE extents and the slot-load census are observations. "Extra-flush", "CLI flag", "Keccak-256", "decoder", "Vec", "message" and "channel" are inferred labels from the call shapes, sizes, constants and strings. The binary was not executed.
- Scope included: every GOT-slot access to `0x64ffe50`; the store condition and the two-flag panic in the setter `0x51cf360`; the poll code from the pair store (`0x5a8707c`) to the write call (`0x5a88864`) and the free that follows. Scope excluded: the bodies of the sponge update `0x5cda910`, finalize `0x5cdad40` and decoder `0x36abb10`; where the setter's argument struct is filled; how the poll obtains the pair stored at `+0x190`; the 100 readers other than the line write.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/mempool_txs_record_115.py --check
python3 -m unittest tests.test_mempool_txs_record_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: one writer, 100 readers

- `0x64ffe50` is in `.bss` (zero at load). Its only relocation is the GOT slot `0x64e0f88`; no `.text` instruction addresses it directly.
- `.text` has 101 `mov r64, [rip+disp32]` loads of the slot. 100 are followed by `0f b6 00` (`movzx eax, byte [rax]`) in 88 functions; one, at `0x51cf3e0`, is followed by `c6 06 01` (`mov byte [rsi], 1`) at `0x51cf3e7`. No instruction stores 0.

## Evidence 2: the setter

- `0x51cf360` is reached through slot `0x64e7428` from `0x2aec025` and `0x2cb7645`. Its second argument (`rsi`) is a struct; the function reads bytes `+0x18` to `+0x23`.
- `0x51cf3da` `cmp byte [rsi+0x20], 0` / `je`: the global is set to 1 only when byte `+0x20` is not zero.
- Bytes `+0x21` (`dl`) and `+0x22` (`cl`): when both are set, `0x51cf3fb` branches to `0x51d0aba`, which passes `0x91fd5f` ("cannot set both batch_by_block and stream_with_block_info", length `0x73` passed) to a panic.
- The binary also holds the CLI names `write-trades` … `disable-output-file-buffering`, `batch-by-block`, `stream-with-block-info` (`0x92ac06` area). Inference: `+0x21`/`+0x22` are `batch_by_block`/`stream_with_block_info`, and `+0x20` is `disable_output_file_buffering`, which matches an extra flush after each line. The tool does not bind field `+0x20` to that name.

## Evidence 3: the poll path to the write

- `0x5a8707c` `cmp r12d, 1` / `jne 0x5a8724f`: the two words at `rsp+0x2318`/`rsp+0x2320` are stored at future `+0x190`/`+0x198` and copied to `+0x2d60`/`+0x2d68`.
- `0x5a8729b` `test rax, rax` / `je 0x5a8869d`: when the first word is zero, `0x5a886a4` loads `r15 = [future+0x2d68]`, and the input is the bytes at `[r15+0x18]` with length `[r15+0x20]`.

## Evidence 4: the record

- `tx_hash` (`+0x10..+0x30`): the poll zeroes 200 bytes at `rsp+0x5c0`, stores `0x88` at `+0xd0` and `1` at `+0xd8`, calls slot `0x64e0148` (`0x5cda910`) with the input still in `rsi`/`rdx`, copies 0xe0 bytes, and calls slot `0x64e0150` (`0x5cdad40`) for 32 bytes at `rsp+0x2310`. Those 32 bytes go to record `+0x10..+0x30`. Inference: Keccak-256 (200-byte state, rate 136, padding byte 0x01).
- `signed_actions` (`+0x0` pointer, `+0x8` length): slot `0x64e87f0` (`0x36abb10`) is called on the same input; when the result tag word is `0x1a2`, the pointer (`+0x10`) and length (`+0x18`) are stored in the record. After the write, the buffer is freed as `capacity * 0x168` bytes. Inference: a decoded Vec of 0x168-byte signed actions.
- The record address is passed at `0x5a8885c`; the call is `0x5a88864` → `0x4e3eaa0`.

## Implementation and comparison

The tool pins 37 instruction byte runs, 9 references, 5 relocations, the panic text, the global's section and the slot-load census. Tests mutate one byte at a time in a copy of the image and expect rejection (9 mutation tests). Alternatives considered: naming field `+0x20` by tracing clap's `FromArgMatches` (bounded out), and emulation (not allowed for this repository).

## Results and limitations

- Result: the global extra-flush byte is set once, to 1, by the node's setup code when one argument flag is set, and is never cleared. The `mempool_txs` record is built from one byte buffer: `tx_hash` is its 32-byte sponge hash and `signed_actions` is its decoded list.
- Limits: the flag name for `+0x20` is an inference; the hash and decoder bodies are not mapped; where the pair at `+0x190` comes from (inferred channel receive) and the non-zero first-word path are not mapped; the census matches one load shape (`mov r64, [rip+disp32]`).
- Next lead: map where the setter's argument struct is built (`[r13]` before `0x2aec025`), to bind `+0x20` to `disable-output-file-buffering`.
