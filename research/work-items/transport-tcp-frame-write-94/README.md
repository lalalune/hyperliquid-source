# transport: node #94 TCP frame write path (compression decision, LZ4 buffer, header, chunks)

Question: across every frame writer that can LZ4-compress a payload, what
compression predicate, compressed-buffer sizing, size prefix, frame header,
write chunk size and default chunk timeout do the node #94 instructions
implement, and where does the can1357 `write.rs` lead differ?

- Component ID: `transport` (`docs/COMPONENTS.md`, "Map frame lengths,
  compression boundaries and error handling without network traffic").
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`
  (`net_utils/tcp/write.rs`), used only for seed addresses and claims to test;
  no code, comments or names copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `transport` research; no gate change.
- Scope: the three writers `0x204b340`, `0x43a17c0` (same layout, +0x2356480)
  and the inline owner future `0x4b363b0`, from the compression decision to the
  per-chunk timeout selection, plus the `(flag, seconds)` argument setup at
  all 12 direct writer call sites (including the two bincode wrappers
  `0x204b0a0`/`0x204b1f0`). Excluded: the lz4_flex compressors
  `0x4e4d600`/`0x4e4dd30`, the write-all/timeout poll `0x2036460`, the stats
  recorder `0x3d2a730`, the raw-path copy, the callers' other arguments and
  message contents, and the error constructors.
- Companions (open separately, not imported): `transport-tcp-frame-read-94`
  (read header/admission/chunks) and `transport-lz4-frame-94` (read-side LZ4).

## Reproduce

```sh
make verify
python3 tools/tcp_frame_write_static.py --out research/work-items/transport-tcp-frame-write-94
python3 -m unittest tests.test_tcp_frame_write_static -v
```

The producer authenticates the input against `provenance/artifacts.json`, parses
sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries. Inside each writer FDE, every fact is an exact
instruction sequence that must occur exactly once; branch, LEA and GOT-slot
targets are decoded from it. It needs only Python 3 (run here with 3.14.7 on
macOS arm64; about 1 s) and never executes the target. `records.json` is its
complete output; the test suite regenerates and compares it.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47 (windows
start at instruction boundaries of the FDE's linear decoding; 21 windows). All
121 `.text` VAs in the `writers`, `wrappers`, `inline_pair` and `callers`
records and in the pinned label setups are instruction starts in GNU objdump's
linear decoding of the owning FDEs.

## Evidence

### Writer census

In all of `.text`:

- `cmp eax,0xf9e` (`3d 9e 0f 00 00`) occurs exactly three times, once in each
  of the FDEs `0x204b340..0x204c216`, `0x43a17c0..0x43a2696` and
  `0x4b363b0..0x4b39004`.
- The only callers of GOT slots `0x5773820` (→ `0x4e4d600`) and `0x5773828`
  (→ `0x4e4dd30`) are one call each in those three FDEs.
- Slot `0x5773818` (→ `0x3d2a730`, the lead's `lz4_stats` sample recorder) is
  called once in each writer and once in each of the five `read.rs` reader FDEs,
  8 owners in total.

Each writer has its own `tcp_chunk` literal (`0x3c4c05`, `0x6f1640`,
`0x707145`).

### Observations per writer (all three)

1. **Compression decision.** `cmp r12,0x401; jb raw`, then
   `movzx eax,WORD [stream+0x90]; and eax,0xfffffffe; movzx eax,ax;
   cmp eax,0xf9e; je raw` with the same target. So the payload is compressed
   only when `len >= 1025` and the u16 at `stream+0x90` is neither 3998 nor 3999.
2. **Compressed buffer.** `mov ecx,110; mul; jo; shr 2; mul 0x28f5c28f5c28f5c3;
   shr 2` gives `len*110/100` (checked for every tested value in the model).
   `lea rsi,[r15+0x18]; mov edi,1; call [0x576e298]` allocates
   `24 + len*110/100` bytes, then `mov [buf],r12d` stores the low 32 bits of the
   input length at offset 0. The output window is `buf+4` with
   `len*110/100 + 20` bytes.
3. **Hash table.** `cmp r12,0xffff; jae`: below 65,535 bytes,
   `alloc(1, 0x2000)` and the compressor behind `0x5773820`; otherwise
   `alloc(1, 0x4000)` and the one behind `0x5773828`.
4. **Result.** `test r15b,1; jne` reaches a LEA of
   `called \`Result::unwrap()\` on an \`Err\` value`, so a compressor error
   panics. Otherwise the length is `compressed + 4`, with an overflow check. The
   stats call follows, and the flag register is set to 1 (`r14b`, or `r13b` in
   `0x4b363b0`). The raw path copies the payload and zeroes the same register.
5. **Frame.** `shr rax,32; je`: a payload of `2**32` bytes or more is rejected.
   Otherwise a 4-byte buffer gets `bswap r12d` (big-endian payload length), the
   flag register is stored at `+4` and the length set to 5, then the payload is
   appended. This is the same `[u32 BE len][flag][payload]` the readers parse.
6. **Chunks.** `mov QWORD [state+X],4000000` follows the frame build. The
   write loop takes `min(remaining, [state+X])` per iteration
   (`cmp rcx,rax; cmovae rcx,rax`) and builds a timed write labelled
   `tcp_chunk` (length 9) for each chunk.
7. **Chunk timeout.** The loop loads an f64 from a field `F+8` and keeps it only
   if the byte at `F` is non-zero (`cmp BYTE [F],0; jne`); otherwise it uses the
   constant 20.0 (`0x20b038`). In `0x204b340`/`0x43a17c0`, `F`/`F+8` are copied
   from the writer argument's first two words (`[rbx]`/`[rbx+8]` →
   `[rbx+0x30]`/`[rbx+0x38]`).

### Who selects 60 s versus 20 s

- Both bincode wrappers (`0x204b0a0`, `0x204b1f0`) write `0` to the argument's
  first word (`mov QWORD [rbx+0x10],0`) and `60.0` to its second
  (`movabs rax,0x404e000000000000; mov [rbx+0x18],rax`). They then pass
  `rdi = rbx+0x10` to `0x204b340`. By rule 7, their chunks use 20.0, not 60.0.
- The inline writer `0x4b363b0` builds its own pair with `xor eax,eax;
  mov [rbx+0x280],rax`, so its flag is constant 0 and its chunks also use 20.0.
- `.text` has exactly 12 direct `call rel32` sites to the three writers. Besides the two wrappers, nine
  build the pair at a call-specific base `D` with the same instruction shape:
  `mov QWORD [rbx+D],imm32; movabs r,60.0; mov [rbx+D+8],r; …;
  lea R,[rbx+D]; mov rdi,R; call`. The tool decodes the ModRM/REX fields and
  requires the stores to precede the LEA. The twelfth (`0x4b5fbc6` →
  `0x4b363b0`) is the inline future's poll, which builds its own pair (see
  above).

  | Call | Writer | Owner FDE | Pair base | `arg0` | Label | Chunk timeout selected |
  | --- | --- | --- | --- | ---: | --- | ---: |
  | `0x1fd7930` | `0x204b340` | `0x1fd7810` | `[rbx+0x58]` | 0 | `write evm kv batch` | 20.0 |
  | `0x2034387` | `0x204b340` | `0x2033080` | `[rbx+0x200]` | 0 | none | 20.0 |
  | `0x203812e` | `0x204b340` | `0x2037ac0` | `[rbx+0x218]` | 0 | `abci_stream send tcp greeting` | 20.0 |
  | `0x20399f7` | `0x204b340` | `0x2039060` | `[rbx+0x158]` | 0 | `send gossip rpc request` | 20.0 |
  | `0x203b588` | `0x204b340` | `0x203a190` | `[rbx+0x200]` | **1** | none | **60.0** |
  | `0x438384e` | `0x43a17c0` | `0x43831e0` | `[rbx+0x218]` | 0 | `abci_stream send tcp greeting` | 20.0 |
  | `0x438726d` | `0x43a17c0` | `0x4386f70` | `[rbx+0x250]` | 0 | from future state | 20.0 |
  | `0x43888d7` | `0x43a17c0` | `0x4387f40` | `[rbx+0x158]` | 0 | `send gossip rpc request` | 20.0 |
  | `0x439f983` | `0x43a17c0` | `0x439f860` | `[rbx+0x40]` | 0 | none | 20.0 |

  Labels: for five calls, the owner sets up `lea rcx,[rip+label];
  mov r8d,len(label)` and a helper call (`0x28c0110`, `0x28c0b90`,
  `0x28c0650`, `0x4b74e50`, `0x4b74ff0`) at most 0x30 bytes before the pair
  build. The tool checks the string bytes and length.
  `research/imported/can1357-literal-classes.json` lists `write evm kv batch`
  and `abci_stream send tcp greeting` under `net_utils/tcp/write.rs`; `send
  gossip rpc request` is not listed. That they name the send is an inference,
  and what the helper does is not analysed. `0x438726d` calls helper
  `0x4b75190` with `rcx`/`r8` loaded from future state `[rbx+0x240]`/`[rbx+0x248]`.
  That label is not resolved statically.

  So exactly one statically visible send path selects the 60.0 s per-chunk
  timeout; every other path, including both wrappers, the inline writer and
  every labelled send (EVM kv batch, ABCI greeting, gossip RPC request), gets
  20.0 s. The 60 s owner `0x203a190` and its zero-flag twin `0x2033080`
  both LEA the text blobs containing `sending abci_state` and `sending evm kvs`.
  Only `0x203a190` also LEAs the blob starting
  `ReplicaCmd::compute_abci_greeting`. Which message each call sends is not
  established.

### lz4_flex correspondence (inference)

From the crates.io archive `lz4_flex-0.11.6.crate` (`373f5ece…854a`, equal to the
crates.io index checksum; the binary's lz4_flex Location paths all name 0.11.6):

- `Cargo.toml` (`1a097ce5…afea`) enables `safe-encode` by default.
- `src/block/compress.rs` (`c30d34ae…0fde`): `get_maximum_output_size(n) =
  16 + 4 + n*110/100`. `compress_into_vec_with_dict` under `safe-encode`
  allocates `vec![0u8; max + 4]`, writes `(input.len() as u32).to_le_bytes()`,
  compresses into `[4..]`, truncates to `4 + compressed_len` and
  `shrink_to_fit`s.
- `compress_into_sink_with_dict` picks `HashTable4KU16` when
  `input.len() < u16::MAX`, else `HashTable4K`.
- `src/block/hashtable.rs` (`23d3814a…a203`) sizes those tables as 4096 `u16`
  (8 KiB) and 4096 `u32` (16 KiB).

The observed sequence is therefore an inlined
`lz4_flex::block::compress_prepend_size`. The two compressor callees are the
u16- and u32-table instantiations, and `0x576e298` is a zeroed allocation
(consistent with the calloc-shaped `0x54c0780`; there is no symbol).

## Implementation and comparison

No Rust implementation. The tool includes a transcribed model (`compresses`,
`compressed_capacity`, `binary_div100`, `size_prefix`, `frame_header`, `chunks`)
and the lead's `reference_capacity`/`reference_prefix`. The model tests check
`binary_div100(x) == x // 100` for 2,008 values, including 2,000 random u64.

Lead corrections:

- **Compressed buffer:** the lead reserves `4 + max(scratch, len)` and describes
  8 KiB/16 KiB as output "scratch". The binary allocates `24 + len*110/100`
  (lz4_flex's bound plus prefix). 8 KiB/16 KiB are the hash table sizes;
  10/10 model lengths differ.
- **Size prefix:** the lead saturates (`unwrap_or(u32::MAX)`); the binary
  truncates (`len as u32`). This matters only for inputs of `2**32` bytes or
  more (2/10 model lengths).
- **`0x3d0900`:** the lead labels it `STATS_BUCKET_NANOS`. In all three writers
  it is the write chunk size (4,000,000 bytes) consumed by the `min(remaining, …)`
  loop.
- **Timeout:** the lead's default is a 60 s frame timeout. The binary applies a
  timeout per 4,000,000-byte chunk, defaulting to 20.0 s. The two bincode
  wrappers and the inline writer select that default, even though the wrappers
  carry 60.0.
- **`0x439f860`'s 60.0:** the lead's `reconnecting_tcp_client.rs` reads the
  `60.0` built in `0x439f860` as a connect timeout. In the bytes, the only
  `60.0` immediate in that FDE (`movabs` at `0x439f958`) is the seconds word of
  the `{0, 60.0}` pair passed to writer `0x43a17c0` at `0x439f983`. Its flag 0
  selects the 20.0 s chunk default (table above). Whether a connect timeout is
  set elsewhere is not analysed.
- **Agreements:** the lead's compression threshold (`>= 0x401`), port rule
  (`(port & !1) != 0x0f9e`) and `[u32 BE][flag][payload]` frame agree with the
  bytes.

Corruption controls (all must refuse):

- threshold immediate
- port immediate
- capacity multiplier
- removed prefix store
- table-split immediate
- small-table size
- compressed flag value 1→2
- flag-store register
- removed `bswap`
- chunk-size immediate
- default-timeout constant retargeted
- timeout seconds field displacement
- injected fourth port compare
- compressor slot relocation addend
- wrapper first word 0→1
- removed caller 60.0 load
- caller label length
- caller pair base moved
- injected direct writer call
- inline pair flag
- truncated ELF

Sensitivity control (must not refuse): setting `0x2034387`'s flag to 1 moves
exactly that call into the 60.0 s selection.

## Results and limitations

| Metric | Value |
| --- | ---: |
| Writers (port-compare and compressor-caller census) | 3 |
| Signatures required exactly once per writer | 16 |
| `lz4_stats` record callers (writers + readers) | 8 FDEs |
| Direct writer calls (wrappers + decoded + inline poll) | 12 (2 + 9 + 1) |
| Calls selecting the 60.0 s chunk timeout | 1 (`0x203b588`) |
| Record and label-setup VAs that are GNU objdump instruction starts | 121 / 121 |
| Model lengths where capacity / prefix differ from the lead | 10 / 10, 2 / 10 |

Validation on this branch (macOS arm64, Python 3.14.7, GNU binutils 2.47 for the
full suite): `make verify`, `make test`, `make catalogue-check`; the new module
(31 tests) also passes with only macOS LLVM tools on `PATH`.

Not established:

- Rule 7 is a static selection. Whether a timeout fires, and what error the
  write-all/timeout poll `0x2036460` returns, is not analysed.
- The meaning of the u16 at `stream+0x90` (the lead's "peer/listener port") is
  not traced. 3998/3999 come from the mask only.
- Which logical message each direct caller sends is not established.
- The compressors are identified by slot, hash table size and lz4_flex source
  shape. Their bodies are not compared instruction by instruction.
- The callee on the `2**32` path (`0x288d050`, or `0x457c3b0` in the other
  two writers) and the raw-path
  copy are not analysed. The census does not cover other writers that never
  compress, or the #115 release.

Gate: none requested; `transport` gates stay false. Next question: what does the
`0x203a190` future send through its 60 s path, and what does its twin
`0x2033080` send with the 20 s default?
