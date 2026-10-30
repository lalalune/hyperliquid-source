# transport: node #94 TCP LZ4 frame-payload decoder

Question: when a `net_utils` TCP frame carries compression flag 1, what limit,
prefix format, allocation and error classes does the decompressor behind GOT
slot `0x5773810` implement, and which `max_len` does each frame reader pass it?

- Component ID: `transport` (`docs/COMPONENTS.md`, "Map frame lengths,
  compression boundaries and error handling without network traffic").
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`
  (`net_utils/tcp/read.rs`, `decompress_lz4_size_prepended_with_limit`), used
  only for claims to test; no code, comments or names copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `transport` research; no gate change.
- Scope: the decompressor FDE `0x3d1abc0..0x3d1b62b` (2667 bytes), its five
  callers' argument setup, and the lz4_flex source lines its Location records
  name. Excluded: the 16/32/64-byte copy fast paths in detail, the error
  constructors `0x3d26e80`/`0x3d26ab0`/`0x3d1ab80` beyond their call sites,
  the timing call `0x4ee3800` before each decompression, the write path and
  `lz4_stats`.
- Companion: the frame header, admission and chunking of the same five readers
  are mapped in `transport-tcp-frame-read-94` (open separately). This packet is
  self-contained and does not import that tool.

## Reproduce

```sh
make verify
python3 tools/tcp_lz4_frame_static.py --out research/work-items/transport-lz4-frame-94
python3 -m unittest tests.test_tcp_lz4_frame_static -v
```

The producer authenticates the input against `provenance/artifacts.json`, parses
sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and checks fixed encodings at pinned VAs. It decodes
rel8/rel32 branch, RIP-relative LEA and GOT-slot targets, and the ModRM/SIB
`[base+disp]` operands at the call sites. It needs only Python 3 (run here with
3.14.7 on macOS arm64; about 1 s) and never executes the target. `records.json`
is its complete output; the test suite regenerates and compares it.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47: the complete
decompressor FDE, the two small error-constructor FDEs, and each caller's
admission, flag store and call window. As an independent cross-check, all 119
pinned VAs inside the analysed FDEs are instruction starts in GNU objdump's
linear decoding of those FDEs.

## Evidence

### Binding and census

`.rela.dyn` relocates GOT slot `0x5773810` to `0x3d1abc0`; no other relocation
targets that address, and no `e8`/`e9` rel32 in `.text` reaches it. A
whole-`.text` scan finds exactly five `call [rip+X]` through the slot:
`0x204aad2`, `0x2264edb`, `0x43a13e2`, `0x47470c9`, `0x4b73a4d`. Each lies in one
of the five `read.rs` reader FDEs. No `jmp [slot]` exists.

The FDE's RIP-relative LEAs reach 16 Location records, all with paths under
`index.crates.io-1949cf8c6b5b557f/lz4_flex-0.11.6/src/` (`sink.rs` and
`block/decompress_safe.rs`). Every relocated pointer to an `lz4_flex` registry
path in the binary names 0.11.6 (`block/compress.rs` 37, `block/decompress_safe.rs`
9, `sink.rs` 12). The two project templates are each loaded by
one LEA in the whole `.text`:

- `0x1ee8cb`: `lz4 bytes over limit @@ [buf.len(): …] @ [uncompressed_size: …] @ [max_len: …]` (LEA `0x3d1b555`)
- `0x20101d`: `decompress_lz4 failure: …` (LEA `0x3d1b342`)

### Wrapper (observations)

Arguments are `rdi` = result, `rsi`/`rdx` = payload pointer/length, `rcx` = limit.

1. `cmp rdx,3; jbe` (`0x3d1abd9`): a payload of 0–3 bytes stores tag 2 at
   `[rsp+0x50]` and calls `0x3d26e80` without either template.
2. `mov ebx,[rsi]` (`0x3d1abee`): the first four payload bytes are read as a
   zero-extended u32 with no byte swap, i.e. little-endian, unlike the frame
   header's big-endian length.
3. `cmp rcx,rbx; jb 0x3d1b4e6` (`0x3d1abf8`): only `max_len < prefix` is
   rejected; prefix equal to `max_len` is admitted. The rejected path builds a
   three-entry argument array in order: input length `r15` (= `rdx`), prefix,
   and `max_len`, then loads the `lz4 bytes over limit` template.
4. Only then: `test rbx,rbx; je`, else `mov edi,1; mov rsi,rbx;
   call [0x576e298]`. The output buffer is sized by the prefix before any block
   byte is decoded. It is the same slot the frame readers use for the frame buffer.
5. On success (`0x3d1b2cf`): `len = min(write position, prefix)`, then
   `Vec {cap = prefix, ptr, len}` is stored. No equality between decoded length
   and prefix is tested.
6. Every decode error reaches `0x3d1b309`. If the prefix is non-zero it calls
   slot `0x576e010` with `(buffer, prefix, 0)` (inferred deallocation), then spills
   `{tag, a, b}` and formats the `decompress_lz4 failure` template via
   `0x3d1ab80`. The result's first word is then `0x8000000000000000`. All five
   callers compare that word with `0x8000000000000000` after the call.

### Error tags and source binding

| Tag | Selected by | lz4_flex Location / check | `DecompressError` variant |
| ---: | --- | --- | --- |
| 0 | `0x3d1b083` `cmp rbp,rax; ja` (literals) and `0x3d1afab` `cmp r14,rbx; ja` (matches) | `decompress_safe.rs:194`, `literal_length > capacity - pos`, with `:196` building `expected`; `:227`, `pos + match_length > capacity` | `OutputTooSmall` |
| 1 | `0x3d1b06e` `cmp rbp,rax; ja` | `decompress_safe.rs:190`, `literal_length > input.len() - input_pos` | `LiteralOutOfBounds` |
| 2 | paths that run out of input (e.g. `0x3d1b2ff`, `0x3d1b40e`), and payload ≤ 3 bytes | — | `ExpectedAnotherByte` |
| 3 | `0x3d1ad46` `test rdx,rdx; je` on the 16-bit offset | — | `OffsetZero` |
| 4 | `0x3d1ad55` `sub rdi,rdx; jb` (offset beyond output) | — | `OffsetOutOfBounds` |

The Location records sit on the overflow branches of the same arithmetic. For
example, `sub rax,rsi; jb` at `0x3d1b065` panics with `decompress_safe.rs:190:33`,
`add r14,r15; jb` at `0x3d1af9c` panics with `:227:12`, and the u32
extension-byte sums (`add ecx,edx; jb` at `0x3d1af2e`/`0x3d1af73`) panic with
`:39:9`.

Inference: source files, pinned by SHA-256, from the crates.io archive
`lz4_flex-0.11.6.crate` (`373f5ece…854a`, equal to the crates.io index checksum):

- `src/block/mod.rs` (`4536cb81…8746`) declares `DecompressError` without a
  `repr`, in the order `OutputTooSmall`, `LiteralOutOfBounds`,
  `ExpectedAnotherByte`, `OffsetZero`, `OffsetOutOfBounds`. That matches the tags
  above and each tag's selecting predicate.
- `src/block/decompress_safe.rs` (`efcae75d…060f`) line 39 is
  `n += extra as u32;`, line 190 is `if literal_length > input.len() - input_pos {`,
  line 194 is `if literal_length > output.capacity() - output.pos() {`, line 196
  is `expected: output.pos() + literal_length,`, and line 227 is
  `if output.pos() + match_length > output.capacity() {`.
- `decompress_size_prepended` reads the size with `u32::from_le_bytes`, and
  `decompress` allocates `vec![0; min_uncompressed_size]` and `truncate`s to the
  decoded length.
- The overflow branches show that these lz4_flex lines were compiled with
  arithmetic overflow checks.

So the wrapper behaves like `lz4_flex::block::uncompressed_size(…)?`, then a
project limit check against `max_len`, then `lz4_flex::block::decompress(rest,
prefix)` with a formatted error.

### Callers pass the admission `max_len`

For every caller, the tool decodes the memory operands of the read.rs admission
`cmp [base+D],r14`, the compression-flag `sete`, the flag test before the call,
and the three argument loads:

| Reader FDE | Admission `max_len` | Limit `rcx` | Flag (store, test) | Payload ptr / len |
| --- | --- | --- | --- | --- |
| `0x2049950` | `[rbx+0x28]` | `[rbx+0x28]` | `[rbx+0x50]`, `== 0 → skip` | `[rbx+0x68]` / `[rbx+0x70]` |
| `0x43a0260` | `[rbx+0x28]` | `[rbx+0x28]` | `[rbx+0x50]`, `== 0 → skip` | `[rbx+0x68]` / `[rbx+0x70]` |
| `0x4b72900` | `[rbx+0x28]` | `[rbx+0x28]` | `[rbx+0x50]`, `== 0 → skip` | `[rbx+0x68]` / `[rbx+0x70]` |
| `0x22615b0` | `[r12+0x28]` | `[r12+0x28]` | `[r12+0x50]`, `!= 1 → skip` | `[r12+0x68]` / `[r12+0x70]` |
| `0x4744160` | `[rcx+0x3d0]` | `[r15+0x3d0]` | `[rcx/r15+0x3f8]`, `!= 1 → skip` | `[r15+0x410]` / `[r15+0x418]` |

In every caller, the limit argument is the slot the frame length was admitted
against, the flag is that slot `+0x28`, and the payload Vec pointer/length are
`+0x40`/`+0x48`. In `0x4744160` the admission uses `rcx` and the call uses `r15`;
`mov r15,rcx` at `0x4747039` sits between the flag store and the allocation. Inference:
the same object is used at the call. This is not followed through the reader's
loop.

## Implementation and comparison

No Rust implementation. `payload_outcome` in the tool is a transcribed model of
the wrapper decision (it does not decode LZ4). `reference_outcome` transcribes
the lead's predicates. Over seven boundary cases (payload 0/3/4 bytes, prefix
equal to and one above `max_len`, and `u32::MAX`), the predicates agree in all
seven.

Lead corrections (observable text and error class, not predicates):

- Over-limit: the binary's message is `lz4 bytes over limit @@ [buf.len(): …] @
  [uncompressed_size: …] @ [max_len: …]`, three values including the compressed
  payload length. The lead has `lz4 decoded bytes over limit @@ [len: …] @
  [max_len: …]`.
- Short payload: the binary returns lz4_flex `ExpectedAnotherByte` through
  `0x3d26e80`, with no project text. The lead defines a separate
  `payload too short: {len} bytes` variant.
- Decode failure: the binary prefixes `decompress_lz4 failure: `. The lead has
  `tcp::read_bytes decompression failure: `.
- The lead cites one call site (`0x204AAD2`); there are five, all with the same
  argument layout.

Corruption controls (all must refuse):

- short-input threshold 3→4
- inverted limit branch
- swapped limit compare operands
- byte swap in place of the prefix load
- moved allocation slot
- OffsetZero tag 3→5
- inverted OffsetOutOfBounds branch
- reordered over-limit argument
- altered over-limit template
- output clamp `cmovae`→`cmovb`
- caller limit displacement `0x28`→`0x30`
- caller flag displacement `0x50`→`0x51`
- broken `mov r15,rcx` link
- an injected sixth call through the slot
- lz4_flex version byte in a Location path
- truncated ELF

## Results and limitations

| Metric | Value |
| --- | ---: |
| Calls through slot `0x5773810` in `.text` | 5 (all frame readers) |
| Other references to `0x3d1abc0` | 0 |
| lz4_flex Location records used by the decompressor | 16 (one crate version) |
| Error tags pinned to selecting branches | 5 / 5 |
| Overflow branches bound to lz4_flex source lines | 5 (lines 39, 190, 194, 196, 227) |
| Callers whose limit equals the admission `max_len` slot | 5 / 5 |
| Pinned VAs that are GNU objdump instruction starts | 119 / 119 |
| Model cases where predicates differ from the lead | 0 / 7 |

Validation on this branch (macOS arm64, Python 3.14.7, GNU binutils 2.47 for the
full suite): `make verify`, `make test` (454 tests, OK), `make catalogue-check`; the new module
(23 tests) also passes with only macOS LLVM tools on `PATH`.

Not established:

- `0x54c0780` has a calloc-like shape (`nmemb*size` with an overflow check,
  jemalloc size-class compare). Inference: it is a zeroed allocation, matching
  `vec![0; n]`. There is no symbol.
- The error constructors and formatter are identified by their call sites and
  arguments only. The panic slots `0x576e118`/`0x576e150` are inferred overflow
  panics from their Location operands.
- The LZ4 sequence decoder itself (token parsing, the 16/32/64-byte copy fast
  paths and the match copy) is checked only at the five error branches and
  five source bindings above. It is not verified instruction by instruction.
- What each caller does with an `Err` (logging, connection teardown) and with
  the decoded Vec, and whether the compressed frame buffer is freed on both
  paths, are not analysed.
- The census covers this slot and these templates only, not other LZ4 users
  (for example `lz4_flex` compression), and not the #115 release.

Gate: none requested; `transport` gates stay false. Next question: what does
each reader do after the call (`0x204aaf5` `je` target onward): which error
text reaches the caller, and are the frame buffer and decoded Vec dropped on
both paths?
