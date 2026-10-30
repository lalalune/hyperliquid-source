# transport: node #94 TCP frame read path (header, admission, compression flag, chunking)

Question: across every copy of the frame reader linked to
`net_utils/src/tcp/read.rs`, what header layout, length admission, compression
predicate, chunk size and progress-log order do the node #94 instructions
implement, and where does the can1357 `read.rs` lead differ?

- Component ID: `transport` (`docs/COMPONENTS.md`, first task "Map frame lengths,
  compression boundaries and error handling without network traffic").
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`
  (`net_utils/tcp/read.rs`), used only for seed addresses and claims to test; no
  code, comments or names copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `transport` research; no gate change.
- Scope: five reader copies, two out-of-line header readers and seven
  `early eof` sites. Excluded: the LZ4 decompressor behind the slot, timeout
  wiring, callers, bincode decode and the write path.

## Reproduce

```sh
make verify
python3 tools/tcp_frame_read_static.py --out research/work-items/transport-tcp-frame-read-94
python3 -m unittest tests.test_tcp_frame_read_static -v
```

The producer authenticates the input against `provenance/artifacts.json`, parses
sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and checks fixed instruction encodings at pinned
VAs, decoding rel32 branch, RIP-relative LEA and GOT-slot targets itself. It
needs only Python 3 (run here with 3.14.7 on macOS arm64; about 1 s) and never
executes the target. `records.json` is its complete output; the test suite
regenerates and compares it.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47
(`objdump -d -M intel --start-address=LO --stop-address=HI`). As an independent
cross-check, all 135 instruction VAs pinned in `records.json` are instruction
starts in GNU objdump's linear decoding of the analysed FDEs.

## Evidence

Coordinates are linked VAs. FDE ranges are `.eh_frame` `[start, end)`.

### Five reader copies, bound to read.rs

A whole-`.text` census finds exactly five sites each of the chunk-cap encoding
`cmp rax,0x3d0900; mov ecx,0x3d0900; cmovb rcx,rax`, `cmp rdi,0x3d0900`, and
RIP-relative LEAs to `tcp read bytes over limit @@ [desc: …` (`0x1eaa25`),
`tcp::read_bytes over limit @@ [len: …` (`0x1f0cba`) and
`WARN >>> … reading bytes for …` (`0x1f228d`). Each lies in exactly one of these
FDEs, one per copy:

| Copy FDE | Bytes | Header read | Admission branch(es) | Flag test | Progress rejoin |
| --- | ---: | --- | --- | --- | --- |
| `0x2049950..0x204ae15` | 5317 | call `0x20485e0` | `0x204a0b9` jae | `0x204a1d9` | fallthrough `0x204a9e2` |
| `0x43a0260..0x43a1725` | 5317 | call `0x439edd0` | `0x43a09c9` jae | `0x43a0ae9` | fallthrough `0x43a12f2` |
| `0x4b72900..0x4b73d7c` | 5244 | inline `0x4b731f2` | `0x4b730bc` jae, `0x4b7320f` jb | `0x4b73215` | jmp `0x4b73a1b` |
| `0x22615b0..0x22689f0` | 29760 | inline `0x2263e80` | `0x2263ea2` jb | `0x2263ea8` | fallthrough `0x2264dd0` |
| `0x4744160..0x474822f` | 16591 | inline `0x474712a` | `0x4747020` jb | `0x4747026` | fallthrough `0x4745386` |

`.rela.dyn` has 20 `R_X86_64_RELATIVE` Location records whose path pointer is
`/home/ubuntu/hl/code_Mainnet/net_utils/src/tcp/read.rs` (`0x1e3bd5`): five groups
for lines 19, 24, 35 and 51. Each copy LEAs its own group's line 35 next to the
over-limit formatting and line 51 at the chunk-slice bounds panic
(`records.json` `read_rs_locations`). The can1357 seeds `0x2049950`,
`0x43a0260` and `0x4b72900` are the first three; the two inlined copies are
not in the lead.

### Observations per copy

- **Header.** Out-of-line readers `0x20485e0` and `0x439edd0` set a 5-byte
  read (`mov QWORD [rbx+0x10],5`, `mov ecx,5`) into `[rbx+0x50]`, then
  `mov ecx,[rbx+0x50]; bswap ecx; movzx eax,BYTE [rbx+0x54]`. The three inline
  copies load a dword at frame offset D, `bswap` it and `movzx` the byte at
  D+4 from the same base. Layout: big-endian u32 length, then one flag byte.
- **Admission.** `mov r14d,<len32>` zero-extends the length; `cmp [max_len],r14`
  is followed by an unsigned `jae` to, or `jb` around, the flag test. Length
  equal to `max_len` is admitted. The over-limit target formats the
  `over limit` message within 0x100 bytes and never reaches the frame-buffer
  allocation below.
- **Compression flag.** `cmp <flag8>,1; sete` stores "compressed" only for
  flag byte 1; 0 and 2–255 are raw.
- **Allocation.** `test r14,r14` skips allocation for length 0; otherwise
  `mov edi,1; mov rsi,r14; call [0x576e298]` (relocated to `0x54c0780`).
- **Chunking.** After each chunk, `offset` saturating-adds the chunk length and
  is stored. `cmp rdi,4000000; jb` either goes straight to
  `remaining = len - offset; jbe done` or first reaches the `WARN … reading
  bytes for` formatting and then rejoins that check. The next chunk is
  `min(remaining, 4,000,000)`.
- **Timeouts.** Each copy LEAs its own `tcp_bytes` literal within 0x50 bytes
  before `movabs rcx,0x4044000000000000` (40.0), and its own `tcp_read_exact`
  before `movabs rcx,0x4034000000000000` (20.0).
- **Decompression.** Each copy has a pinned `call [0x5773810]` (relocated to
  `0x3d1abc0`). In `0x2049950` it follows `cmp BYTE [rbx+0x50],0; je` on the
  stored compression flag; the branch condition is not checked by the tool.

### Early EOF is std `UnexpectedEof` from tokio's `read_exact`

All seven `early eof` LEAs (`0x7d0cd4`) are followed directly by `mov edx,9;
mov edi,0x25; call [0x576ee60]` (relocated to `0x4edac60`). They are in the two
header readers, the three inline copies and the 702-byte FDEs `0x2034eb0` and
`0x4387c80`, which `0x2049950`/`0x22615b0` and `0x43a0260`/`0x4b72900`/`0x4744160` call.

Inference, with exact-version sources:
- `.comment` names rustc 1.94.1 `e408947bf`; the 1.94.1 rust-src at that commit
  (`library/std/src/io/error.rs`, SHA-256 `2b819a8d…3c82`) declares
  `ErrorKind` without a `repr`, and its 38th variant (discriminant 37 = 0x25) is
  `UnexpectedEof`.
- The header reader's underflow panic (`sub rbp,rax; jb 0x2048761`) loads the
  Location for `tokio-1.44.2/src/io/read_buf.rs:182`, which is
  `self.capacity() - self.filled` in `ReadBuf::remaining`. tokio 1.44.2
  (crate SHA-256 `e6b88822…9c48`, equal to the crates.io index checksum)
  `src/io/util/read_exact.rs` (SHA-256 `fce472d6…465a`) defines
  `fn eof() -> io::Error { io::Error::new(io::ErrorKind::UnexpectedEof, "early eof") }`.

So the lead's "error code `37`" is the standard-library `ErrorKind`
discriminant raised by tokio's `ReadExact`, not a project error code.

## Implementation and comparison

No Rust implementation. `tools/tcp_frame_read_static.py` includes a small
transcribed model (`admitted`, `compressed`, `chunk_plan`) of the observed
predicates, and the lead's progress rule as `reference_plan`. It is compared
over lengths 0, 1, 4e6−1, 4e6, 4e6+1, 8e6−1, 8e6, 8e6+1 and 2^32−1. Chunk sizes
agree for every length. For every length ≥ 4,000,000 the binary reaches the
`WARN` formatting once more than the lead (after the final chunk, where the
lead requires `offset < total_len`). The model is not executed target code.

Corruption controls (all must refuse): flag immediate 1→2, inverted admission
branch, admission compare register, chunk-cap immediate, gate `jb`→`jbe`,
broken progress rejoin, removed header `bswap`, inline flag offset D+5,
early-eof kind 0x26, retargeted over-limit LEA, decompression slot shifted by
8, an extra chunk-cap encoding injected outside the copies, an altered
`read.rs` path byte, and a truncated ELF.

## Results and limitations

| Metric | Value |
| --- | ---: |
| Reader copies (census of 5 signatures over all of `.text`) | 5 |
| Length admission branches | 6 |
| Out-of-line 5-byte header readers | 2 |
| `early eof` constructions | 7 |
| read.rs Location records | 20 (5 × lines 19/24/35/51) |
| Pinned instruction VAs that are GNU objdump instruction starts | 135 / 135 |
| Model lengths differing from the lead | 6 / 9 (all ≥ 4e6, final-chunk WARN only) |

Validation on this branch (macOS arm64, Python 3.14.7, GNU binutils 2.47 for
the full suite): `make verify`, `make test` (453 tests, OK),
`make catalogue-check`. The new test module runs without GNU or LLVM binutils.

Not established:
- The LZ4 path behind `0x3d1abc0` (size prefix, decoded-length limit and error
  strings in the lead) is not analysed.
- Timeout wiring: which branch applies the 40.0/20.0 values and when no
  timeout is used.
- `0x4edac60` as `io::Error::new` and `0x54c0780` as alloc versus alloc_zeroed are
  inferred from arguments only. `ErrorKind` numbering is from exact-commit
  source, not a binary table.
- Progress rejoin for fallthrough copies is a layout fact (the `WARN` LEA lies
  between the gate fallthrough and the remaining check); whether a `WARN` line
  is emitted at runtime depends on code not analysed here.
- The census covers these encodings and literals only, not every TCP reader,
  caller, `read_deserialized` wrapper or the #115 release.

Gate: none requested; `transport` gates stay false. Next question: does
`0x3d1abc0` read a little-endian u32 size prefix and reject decoded lengths
above the caller's `max_len`, and which error strings does it construct?
