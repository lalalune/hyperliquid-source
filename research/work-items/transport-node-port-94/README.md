# transport: node #94 NodePort port arithmetic (base ports, validator offset, overflow panics)

Question: at every site where node #94 turns a NodePort endpoint into a TCP
port, which base port is used, how is a local-validator index folded in, and
what happens when the result does not fit in a u16? Where does the can1357
`node_port.rs` lead differ?

- Component ID: `transport` (`docs/COMPONENTS.md`: TCP framing, LZ4,
  channels, rate limits and reconnects; path rule `net_utils/*`).
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`
  (`net_utils/node_port.rs`), used only for seed addresses and claims to test;
  no code, comments or names copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `transport` research; no gate change.
- Scope: the local-validator port computation at all 10 sites, the base port
  selection that feeds it, and its overflow branches. Excluded: the
  non-local-validator branch of the 5 constant-base sites, what each site does
  with the socket address (bind, connect, retry), the names of the six
  discriminants, and release #115.

## Reproduce

```sh
make verify
python3 tools/node_port_static.py --out research/work-items/transport-node-port-94
python3 -m unittest tests.test_node_port_static -v
```

The producer authenticates the input against `provenance/artifacts.json`, parses
sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; under 1 s). `records.json` is
its complete output; the test suite regenerates and compares it.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47, in 35
windows: every site, both dispatches and their arms, every panic stub and the
two panic helpers. All 61 code VAs in the `sites` records are instruction
starts in those windows.

## Evidence

### Censuses

- `.text` contains exactly 10 occurrences of `mov r16,1000; mul r16; jo rel32`
  (`66 b8+r e8 03 66 f7 e0+r 0f 80`), with the same register in both. Their
  FDEs are `0x1fd4570`, `0x2037ac0`, `0x2039060`, `0x22c54a0`, `0x43831e0`,
  `0x43848f0`, `0x4387f40`, `0x438ed70`, `0x454c2b0` and `0x47b4950`. These are
  the lead's ten seed functions.
- The u16 sequence `[4001, 4002, 4003, 4004, 3998, 3999]` occurs exactly three
  times in file-backed sections, all in `.rodata` (`0x3c4ce0`, `0x3d8450`,
  `0x6f16a2`). Each is referenced by exactly one RIP-relative LEA, from
  `0x2037ac0`, `0x22c54a0` and `0x43831e0` respectively.

### Base port: three shapes

| Shape | Sites | How the base port is chosen |
| --- | --- | --- |
| `table` | `0x2037ac0`, `0x22c54a0`, `0x43831e0` | `lea r,[rip+table]; movzx r32,WORD [r+rcx*2]`, so `port = table[discriminant]` |
| `jump_table` | `0x438ed70`, `0x47b4950` | `lea rsi,[rip+JT]; movsxd rcx,[rsi+rcx*4]; add rcx,rsi; jmp rcx`. The six arms (`0x6efb04`, `0x6fa3bc`) each do `mov si,port` and reach one join. A direct path also falls into the 4002 arm. |
| `const_cmp` | `0x1fd4570` (4001), `0x2039060` (4002), `0x4387f40` (4002), `0x454c2b0` (4003), `0x43848f0` (4004) | constant `add eax,base` |

In both tables and both jump tables, discriminants 0–5 map to 4001, 4002,
4003, 4004, 3998 and 3999. No bounds check on the discriminant was found
before the table load or the dispatch.

### Local-validator offset

At all 10 sites:

- **Offset:** `index * 1000` is a 16-bit `mul`; `jo` goes to a panic stub.
- **Address:** the local address is built as `0x0100007f`, i.e. bytes
  `7f 00 00 01`, which is `127.0.0.1`. This is either one `mov ecx,0x100007f`,
  or `mov e?x,0x1000000` plus `mov e?x,0x7f` before the `or`.
- **Add check:** the `table` and `jump_table` shapes check the add with
  `add r16,r16; jb` to a stub. The `const_cmp` shape compares first:
  `movzx ecx,ax; cmp ecx,0xffff-base; ja` to a stub, then `add eax,base`. The
  tool requires `bound == 0xffff - base` (`0xf05e`, `0xf05d`, `0xf05c`,
  `0xf05b`).
- **Index width:** at 7 sites the index is a byte zero-extended immediately
  before the multiply (`movzx eax,al|cl`). At `0x22c54a0`, `0x438ed70` and
  `0x47b4950` it comes from a byte via `shl 8 … shr 8` (inference; this is not
  tool-checked).

### Overflow is a panic

Every multiply-overflow branch reaches `lea rdi,[0x5719a08]; call [0x576e1b0]`,
and every add-overflow branch reaches `lea rdi,[0x5719a20]; call [0x576e118]`.
At `0x454c2b0` each stub is preceded by `mov r12b,1`.

- **Locations:** both Location records point to
  `/home/ubuntu/hl/code_Mainnet/net_utils/src/node_port.rs`. The multiply is
  line 23 col 63 and the add is line 28 col 14.
- **Slots:** `.rela.dyn` resolves slot `0x576e1b0` to `0x157b4a0` and slot
  `0x576e118` to `0x157b480`.
- **Helpers:** each helper loads a message pointer and `esi = (len << 1) | 1`.
  The messages are `attempt to multiply with overflow` and
  `attempt to add with overflow`.

Inference: this is rustc's arithmetic overflow check (overflow checks enabled in
this build) on a plain `base + index * 1000` in u16.

## Implementation and comparison

There is no Rust implementation. The tool includes a transcribed model,
`local_port(base, index)`, and the lead's `reference_port` (checked_mul/checked_add
returning `Err(PortOverflow)`). The model was evaluated for all six bases and
all u8 indices 0..=255:

- Indices 0..=61 give `base + 1000*index`; the highest port is 65004.
- Indices 62..=65 panic with "attempt to add with overflow".
- Indices 66..=255 panic with "attempt to multiply with overflow".
- The lead agrees on every successful index.

Lead agreements:

- base ports 4001/4002/4003/4004/3998/3999 in discriminant order
- the six-way jump tables in `0x438ed70`/`0x47b4950`
- the 1000 stride
- `127.0.0.1` for local validators
- per-site constants: 4002 at `0x4387f40`, 4003 at `0x454c2b0`, 4004 at
  `0x43848f0`
- the panic blocks at `0x454c47b`/`0x454c48d`

Lead corrections:

- **Error class:** the lead returns `Err(NodePortError::PortOverflow{..})`. The
  binary panics (`attempt to multiply with overflow` /
  `attempt to add with overflow` at `node_port.rs:23:63` / `:28:14`). The
  strings `overflows u16 port range`, `PortOverflow`, `unknown NodePort` and
  `auxiliary_0` do not occur anywhere in the file.
- **Index type:** the lead takes `validator_index: u16`. At 7 of 10 sites the
  binary zero-extends a byte. A u16 index of 256 or more has no counterpart.
- **Constant sites:** the lead describes `0x1fd4570` only as a gossip RPC
  caller. Its port is the constant 4001 (discriminant 0), and `0x2039060` uses
  the constant 4002.

Cross-reference (inference, not established): the TCP write path's
compression bypass `(u16 [stream+0x90] & !1) == 0xf9e` excludes exactly
discriminants 4 and 5 (3998/3999) of this table.

Corruption controls (all must refuse):

- stride 1000→1001
- `mul` register mismatch
- `cmp` bound not `0xffff - base`
- constant base changed
- jump-table arm port changed (dispatched arm and fall-through arm)
- u16 table entry changed
- table LEA retargeted
- local IP byte changed
- `jb` turned into `jae`
- multiply Location line changed
- add-panic slot relocated to the multiply helper
- injected `mul` site
- truncated ELF

## Results and limitations

| Metric | Value |
| --- | ---: |
| `mov r16,1000; mul` sites | 10 |
| u16 port tables / jump tables | 3 / 2 |
| Constant-base sites | 5 |
| Sites whose overflow branches reach the two `node_port.rs` panics | 10 / 10 |
| Max validator index without panic (every base) | 61 |
| Code VAs that are GNU objdump instruction starts | 61 / 61 |

Validation on this branch (macOS arm64, Python 3.14.7, GNU binutils 2.47 for
the full suite): `make verify`, `make test`, `make catalogue-check`. The new
module (20 tests) also passes with only macOS LLVM tools on `PATH`.

Not established:

- The non-local branch (peer IPv4 from the endpoint's bytes 1–4, offset 0) is
  read from the `table` sites' instructions but is not tool-checked. For
  `const_cmp` it is not analysed.
- The names of discriminants 0–5 are not established. Only the
  `gossip_rpc_requests`/`consensus_rpc` text occurs in the file, and it is not
  bound to a discriminant here.
- Whether a validator index of 62 or more can reach these sites (where it comes
  from) is not analysed.

Gate: none requested; `transport` gates stay false. Next question: which
discriminant each `const_cmp` caller passes, and where the validator index
originates.
