# transport: reconstruct node #115 native LZ4 stream-management entry points

This packet lets a reimplementer rebuild, as executable Python, the fourteen small native LZ4 library entry points that node #115 carries for stream setup (`compressBound`, stream/decode-stream/HC-stream create, init, reset, free, `setStreamDecode`, `setCompressionLevel`) and the dictionary preload `loadDict` (64 KiB window, 3-byte stride, 12-bit multiplicative hash into a 4096-slot u32 table). Each function is evaluated from its own bytes, never by running the target, and 16,106 generated cases agree with the independent re-implementation, with 46 of 46 negative controls detected.

- Component ID: transport (Network transport; first task, compression boundaries and error handling)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository main at packet creation; no reference source copied
- Claim status: observation (bytes, decoded instructions, evaluator results); labels such as `LZ4_loadDict` are inference from the vendored lz4-sys census names and the matching constants
- Scope included and excluded: the 14 functions below only. The big compress/decompress kernels, the HC compressor and the Rust-side `lz4` users are excluded; no frame header or channel logic is touched.

## Reproduce

```
python3 tools/transport_lz4_stream_api_115.py --out research/work-items/transport-lz4-stream-api-115
python3 -m unittest tests.test_transport_lz4_stream_api_115
```

Standard library plus `tools/elf_index.py` only. The tool checks the input SHA-256 first, reads section/FDE/relocation tables with `struct`, never calls an external program, and writes deterministic files (fixed PRNG seed, no clocks or paths). The node binary is never executed.

## Evidence

Coordinates are virtual addresses in the unstripped-section image. Function extents are FDE start to next FDE start (`summary.json`, with per-body SHA-256).

| Function | VA | Behaviour recovered |
| --- | --- | --- |
| compressBound | 0x62e5bf0 | n > 0x7e000000 gives 0, else n + n/255 + 16 (signed multiply-high division) |
| initStream | 0x62e5c20 | size < 0x4020, null or non-8-aligned pointer give 0; else zero 0x4020 bytes, return p |
| createStream | 0x62e5c60 | malloc(0x4020), init on success, NULL on failure |
| resetStream | 0x62e5c90 | tail-call memset(p,0,0x4020) |
| freeStream / freeStreamDecode / freeStreamHC | 0x62e5ca0 / 0x62ed7c0 / 0x6300640 | free only non-null, return 0 |
| loadDict | 0x62e5cd0 | reset, currentOffset = 0x10000; size <= 7 returns 0; window clamps to the last 0x10000 bytes; table[(read64(p)*0xcf1bbcdcbb000000)>>52] = p - base, p += 3 while p <= end-8; returns the clamped size |
| createStreamDecode | 0x62ed7a0 | calloc(1,0x20) |
| setStreamDecode | 0x62ed7f0 | zero +0, store sign-extended size at +0x18, zero +0x10, +8 = dict+size only when size != 0, return 1 |
| setCompressionLevel | 0x6300670 | level <= 0 gives 9, else min(level,12), 16-bit store at +0x40024 |
| createStreamHC | 0x6300690 | calloc(1,0x40038), then level 9 |
| initStreamHC | 0x63006c0 | size < 0x40038, null or misaligned give 0; else zero 0x40030 bytes, level 9 |
| resetStreamHC | 0x6300710 | init with full size, then apply the supplied level |

Import stubs (memset, malloc, calloc, free) are identified by `.rela.plt` JUMP_SLOT names mapped through `.plt` `jmp *slot` entries, listed in `summary.json`. `instructions.tsv` is the decoded listing of all selected extents (204 instructions) produced by the tool's fixed-pattern decoder.

## Implementation and comparison

`tools/transport_lz4_stream_api_115.py` contains (1) a byte-pattern x86-64 decoder limited to the opcodes these bodies use (unknown opcodes raise a fault), (2) a concrete evaluator with a sparse memory (writes, fill regions, deterministic pseudo-random background bytes for dictionary reads) and recorded external calls (`memset`, `malloc`, `calloc`, `free`), and (3) an independent Python specification of each function that never touches the evaluator. For every case the observable result is the return value plus the ordered effect trace (memset/store/malloc/calloc/free); evaluator and specification must be equal.

Case classes: 7,019 compressBound (edges, multiples of 255 ±1, near the 0x7e000000 cap, random 32-bit); pointer/size grids and random inputs for the two init functions; allocator success/failure; free/reset pointers; level clamp across signed and unsigned extremes; 2,500 setStreamDecode inputs including negative sizes; loadDict sizes 0..600 with random bases, plus sizes at and beyond the 64 KiB window and negative (>= 2^31) sizes.

Negative controls (46): 17 deliberately wrong specifications (wrong divisor, off-by-one gates, missing alignment test, short clear, wrong level cap, wrong hash shift, wrong stride, wrong window, unsigned size, ...); 24 single-byte corruptions of immediates/conditions/offsets inside the selected bodies; and 5 input/range controls (truncated image, flipped byte in the image, non-FDE start, unmapped VA, entry outside the extents). Controls run on a subsample (first 60 plus every k-th case, with a lowered step limit and loadDict sizes <= 600 or negative); the full-run cases use the unreduced list.

## Results and limitations

`measure.json`: cases 16,106, agree 16,106, negative controls 46, detected 46. Maximum resident memory is far below 1.5 GB. `cases.tsv` is a 300-row sample (digest of expected effects), not the full case list; the rest regenerate from the fixed seed.

Limits: this verifies behaviour of the bytes under the evaluator's model of x86-64 and of libc stubs; real allocator addresses, alignment of malloc results and memory contents are modelled, not observed. Dictionary reads use pseudo-random background bytes, so the hash/table logic is checked but not against real LZ4 streams. Reachability from the Rust transport code (which lz4 calls hl-node actually makes) is not shown here. No progress gate is requested.

Next question: the LZ4 block decoder `0x62eea20` (about 21 KB) and the fast compressor `0x62e5d90`, using the same evaluator.
