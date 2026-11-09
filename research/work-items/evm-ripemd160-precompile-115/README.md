# evm: node #115 RIPEMD-160 and SHA-256 precompile hash paths (addresses 0x03 / 0x02), reconstructed and machine-checked

The reconstruction can now reproduce both hash precompile bodies of node #115 as executable models: the 80-step two-line RIPEMD-160 block function `0x5c3ce60` with its absorb/pad/finish wrapper `0x5bed950`, and the SHA-256 wrapper `0x5bed690` with the portable arm of its block function `0x5c63ed0`; this fixes the block counts, the tail-copy and zero-fill calls, the little-endian (RIPEMD) and big-endian (SHA-256) bit-length trailers, the one-block/two-block boundary at tail length 56 and the result layouts (20 digest bytes right-aligned in a zero-filled 32-byte word, versus the plain 32-byte digest), checked against the real machine bytes on 20,512 cases with 123 negative controls.

- Component ID: `evm`
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`. No reference source was read or copied; the RIPEMD-160 model is written from the published definition and checked against six published digests, the SHA-256 model derives its constants from the first primes and is checked against the standard library's SHA-256 on every case.
- Claim status: addresses, relocations, FDE bounds, byte patterns and the machine-byte comparison are observations; the reading of `0x5bed950` / `0x5bed690` as the 0x03 / 0x02 precompile hashes and of the table slots as the precompile registry are inferences; gas charging, the registry caller and the CPU-feature arms of the SHA-256 block function are unresolved (not covered).
- Scope included and excluded: the four hash bodies, the relocations that wire the block functions into the wrappers, the memcpy/memset/panic imports as recording stubs, and the portable arm of the SHA-256 block function. Excluded: gas charging, the registry that selects a body by address, output wrapping (`PrecompileOutput`), the identity body, the SHA-256 hardware arm (tail jump to `0x5c66b90`) and the CPU-probe arm (cpuid helpers `0x5c66b50` / `0x5c66b70`), and every host effect.

## Reproduce

From the repository root with Python 3 and the authenticated #115 artifact:

```sh
python3 tools/ripemd160_precompile_115.py --out research/work-items/evm-ripemd160-precompile-115
python3 -m unittest tests.test_ripemd160_precompile_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/evm-ripemd160-precompile-115 && sha256sum -c MANIFEST.sha256)
```

Repeatability check (two output directories, different hash seed and time zone):

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/ripemd160_precompile_115.py --out <tmp-dir>/one
PYTHONHASHSEED=937 TZ=Pacific/Honolulu python3 tools/ripemd160_precompile_115.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

The tool first checks the binary SHA-256 and stops on a mismatch. It reads ELF section, relocation and unwind records through the shared `tools/elf_index.py` and `tools/fde_extents.py` parsers, never calls an external program and never executes the binary. A run takes about 140 s and well under 1 GB. The SHA-256 digests in the cases come from the model and are compared to `hashlib` inside the tool; `hashlib` is the only independent oracle, the RIPEMD-160 oracle is the six published digests.

## Evidence

All addresses are virtual addresses of the #115 image. Everything below is produced by the tool from file bytes ([functions.tsv](functions.tsv), [slots.tsv](slots.tsv)).

| Role | VA range | Bytes |
| --- | --- | --- |
| RIPEMD-160 wrapper | `0x5bed950`-`0x5bedbc7` | 631 |
| RIPEMD-160 block function | `0x5c3ce60`-`0x5c3e4eb` | 5,771 |
| SHA-256 wrapper | `0x5bed690`-`0x5bed950` | 704 |
| SHA-256 block function (all arms) | `0x5c63ed0`-`0x5c66b4f` | 11,391 |

Slot `0x64bff80` (RELATIVE, addend `0x5bed690`) and slot `0x64bff88` (RELATIVE, addend `0x5bed950`) are adjacent entries of one pointer table. Slot `0x64ec328` (RELATIVE, addend `0x5c3ce60`) is the RIPEMD wrapper's block pointer: it is read at `0x5bed9e7` and `0x5bedb0f` and called at `0x5bed9f7`, `0x5bedb1f`, `0x5bedb5c` and `0x5bedb6f`. Slot `0x64e1420` (RELATIVE, addend `0x5c63ed0`) is the SHA-256 wrapper's block pointer, called at `0x5bed727` and `0x5bed8b8` and read at `0x5bed841`. `0x5c3ce60` has no direct call site anywhere in `.text` (swept over every `e8`/`e9`) and no RIP-relative reference, so its slot is its only reference. Slots `0x64df508` and `0x64df750` are the imported memcpy and memset (symbol-bound relocations 7 and 10); `0x64df870` is a RELATIVE pointer used by the overflow panic arms of both wrappers.

RIPEMD-160 block function ([constants.tsv](constants.tsv), [rotations.tsv](rotations.tsv), [opcodes.tsv](opcodes.tsv)): the eight non-zero round constants `5a827999 6ed9eba1 8f1bbcdc a953fd4e` (left) and `50a28be6 5c4dd124 6d703ef3 7a6d76e9` (right) each occur exactly 16 times as four-byte immediates, one per step of their round. Every data rotation amount 5..15 occurs 16 times, as the model's two shift tables require (80 + 80 steps); rotate-by-10 occurs 158 times against the model's 160; the two missing ones are not explained here (the machine comparison below shows the model's arithmetic is still exact). The body has 654 `add`, 318 `rol`, 128 `and`, 127 `not`, 64 `or` and 128 `xor` instructions.

RIPEMD-160 wrapper (arguments rdi = result, rdx = data, rcx = length; rsi is overwritten before use):

1. `cmp rcx,0x40; jae`: below 64 bytes the whole input is copied to a stack buffer by one memcpy and no block is compressed; otherwise `rcx >> 6` blocks are compressed one call each, then the tail (`rcx & 0x3f`, possibly 0 bytes) is copied by one memcpy.
2. The byte `0x80` is stored at `buffer[tail]`; if `tail != 63` the remaining `63 - tail` bytes are cleared by one memset.
3. The bit length `(blocks << 9) | (tail << 3)` is stored as a native (little-endian) u64. If `tail ^ 0x38 > 7` (tail below 56) it goes to bytes 56..63 of the same block and one block is compressed. Otherwise (tail 56..63) that block is compressed first, then a zeroed block holding the length at bytes 56..63.
4. The five chaining words are stored right-aligned into the 32-byte result (12 zero bytes first) and the result pointer is returned in `rax`.
5. The block counter has a guard (`>> 0x3a` non-zero panics); it can only trigger for inputs of 2^64 bytes or more, so it is unreachable and reported as such, not exercised.

SHA-256 wrapper ([sha-constants.tsv](sha-constants.tsv)): the same skeleton with three differences, all read from bytes: (a) the block function is called ONCE for all full blocks with the block count in `rdx`, then once (count 1) per padding block; (b) the bit length is byte-swapped (`bswap`, big-endian) before it is stored; (c) the result is the eight chaining words byte-swapped by an SSE sequence (`punpck*bw`, `pshuflw/hw 0x1b`, `packuswb`) into the plain 32-byte digest. Initial state words come from two 16-byte constants in read-only data.

SHA-256 block function: it starts by reading a feature byte at `0x64fe3f9`: `0xff` runs the probe arm (cpuid helpers) and stores the result; value 1 tail-jumps to `0x5c66b90`; any other value, including a probe result of zero, falls to the portable loop at `0x5c63fc6`. The portable loop (3,471 decoded instructions, 576 `rol`-by-immediate, 704 `xor`, 192 `and`, 96 `shr`, 16 `bswap`) processes `rdx` blocks. All 64 round constants appear as immediates in it. This packet runs the portable arm with the feature byte at 0; the other two arms are not modelled. That the byte's value 1 means a hardware SHA arm is an inference.

## Implementation and comparison

The models are `compress_model` / `padded_blocks` / `wrapper_model` (RIPEMD-160) and `sha_compress_model` / `sha_wrapper_model` (SHA-256) in `tools/ripemd160_precompile_115.py`. The same file carries the shared x86-64 interpreter skeleton used by other merged tools, extended here by three SSE instructions (`punpckhbw`, `packuswb`, `pshufhw`) that the SHA-256 result shuffle needs, with memcpy, memset, the panic pointer and (for the stub runs) the block pointer replaced by recording contract stubs. Nothing is executed natively; the interpreter runs the file bytes.

Cases (counts are in [measure.json](measure.json); denominators):

- RIPEMD-160: 6 published digests (model and machine bytes); 6,000 block-function cases (random, all-zero and all-0xff blocks, extreme chaining words; 10,728,000 machine steps); 4,000 wrapper cases with the block function stubbed by the model (ordered event list and 32 result bytes compared; lengths 0..132 exhaustively, selected lengths around 184, 192, 248, 256, 312 and 320, and random lengths up to 329); 2,000 wrapper cases with the real block bytes (lengths below 200; result and memcpy/memset call list compared).
- SHA-256: 6 standard-library comparisons through the machine bytes; 4,000 portable-arm block cases (13,908,000 machine steps); 3,000 stubbed wrapper cases (event list including the block count of each call, and the digest); 1,500 wrapper cases with the real block bytes.

Negative controls ([controls.tsv](controls.tsv), [equivalent-mutants.tsv](equivalent-mutants.tsv)): 123 deliberately wrong variants, 121 detected and 2 shown to be behaviour-equivalent. RIPEMD-160: 45 model variants (a table entry changed in each permutation or shift table, each round constant, the round boolean functions, left/right function order, rotate-10, a wrong cross combination, the final addition dropped, a wrong initial word, pad byte 0x81, split at 55 or 57, big-endian length, byte-count length, digest placed left of the padding), 22 byte corruptions in the block function (twelve rotate immediates, ten constant bytes) and 10 in the wrapper (threshold, tail mask, shifts, pad byte, memset count, the two-block test). SHA-256: 23 model variants (round constants, every rotation amount of the four sigma functions, choose and majority replaced, wrong initial word, pad byte, split, little-endian length, byte-count length), 10 rotate-immediate corruptions in the portable arm and 6 in the wrapper. Range controls (7): wrong binary hash, address that is not an unwind start, address outside every section, address past the last unwind record, input pointer outside mapped memory, result pointer outside memory, memset of a non-zero byte.

The two equivalent mutants are `xor r13d,0x38` changed to `0x39` in the RIPEMD wrapper (only bit 0 differs, so "above 7" selects the same tails) and `cmp r13d,7` changed to `6` (the value 7 is a 63-byte tail, which already left through the earlier `cmp r13,0x3f` branch). Both patched images give identical results over 82 control lengths.

## Results and limitations

- 20,512 comparisons, 0 mismatches; 123 negative controls, 121 detected, 2 equivalent with the argument above, 0 missed.
- Limits: inputs above about 330 bytes are not run; the panic arms are documented but unreachable; the SHA-256 hardware and probe arms are not run; the interpreter models the instructions of these bodies only; whether the table at `0x64bff80` is the registry and which addresses map to its slots is not shown here; no gas path. No gate is requested.
- Next question: the caller that reads the table at `0x64bff80` and the per-address gas charges of the 0x02 / 0x03 bodies in node #115 (`60 + 12 * words` and `600 + 120 * words` in the public specification).
