# RE-009-evm-kv-schema-94: how does node #94 encode HyperEVM RocksDB keys and values?

- **Component ID:** storage (`db/src/block_reader.rs`, `l1/src/evm/evm_db.rs`, `db/src/db_hub.rs`).
- **Target release and full SHA-256:** Linux x86-64 **hl-node #94**,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- **Source commit / reference commit:** branch cut from `1f8c67c63ca4`; can1357 reference
  submodule `999556f6e0a4`, used as leads only.
- **Claim status:** *observation* for the key bytes of the three state tables and the height key,
  the label prefix, the account value fields and their omission rules, the code-gated serializer
  flag, the code-to-decoder bindings and the raw get arguments. *Inference* for the names
  (account, storage, code, balance, nonce, code hash, rmp field meanings) and for rmp-serde as the
  codec. *Unresolved*: which code owns the height and hash getters, the `Bytecode` wire form, and
  five concat sites listed below.
- **Scope included:** key construction, the read path down to the value decoder call, the write
  path down to the batch put, and the three value encoders.
  **Excluded:** decoder bodies, `Bytecode` serialization, the block record (0x398 bytes) layout,
  cache behaviour of the writers, runtime data, and any #115 or visor claim.

**Bounded question.** For the HyperEVM databases, what exact bytes form a RocksDB key and a value?

**Answer** (`K` = the 2-byte database label):

| table | code | label | key | stored value |
| --- | --- | --- | --- | --- |
| account | 24 | `Ea` | `K ++ address[20]`, 22 bytes | map with `b`, `n`, `c`, each omitted at its default |
| storage | 26 | `Es` | `K ++ address[20] ++ slot[32, big endian]`, 54 bytes | bin8 of 32 big-endian bytes |
| code | 25 | `Ec` | `K ++ hash[32]`, 34 bytes | enum `Bytecode` (4 variants), wire form unresolved |
| block by height | unresolved | same prefix layout | `prefix ++ height[8, big endian]` | decoded by `0x17edf80`, 0x398 output bytes |

The account value is a MessagePack map holding only non-default fields, in this order:

| name | struct offset | omitted when | value |
| --- | --- | --- | --- |
| `b` | 0x00 | all 32 bytes are zero | bin8 of 32 big-endian bytes |
| `n` | 0x40 | zero | unsigned integer |
| `c` | 0x20 | equals `keccak256("")` | bin8 of the 32 stored bytes |

So a default account is the single byte `80`, and an account with only nonce 5 is `81 a1 6e 05`.

## Reproduce

Working directory: repository root. No external program is run and the binary is never executed.

```sh
python3 tools/artifacts.py verify
python3 tools/evm_kv_schema.py --out research/work-items/RE-009-evm-kv-schema-94
python3 -m unittest tests.test_evm_kv_schema
sha256sum -c research/work-items/RE-009-evm-kv-schema-94/MANIFEST.sha256
```

The manifest check runs with the folder as working directory. The tool needs Python 3 with the
standard library plus `tools/elf_index.py` and `tools/fde_extents.py`, takes about 10 s, and
refuses any binary with a different digest.

Generated files: `evm-kv-schema.json` (all tables, 43 rip pins, 93 byte pins, worked examples) and
`key-concat-sites.tsv` (27 call sites). Every number comes from ELF bytes read with `struct`, so
the output does not depend on a binutils version. objdump was used only to read code by hand.

## Evidence

Coordinates are ELF virtual addresses; FDE ends are exclusive.

### Keys

All three state builders read the prefix from `self+0x8` (pointer) and `self+0x10` (length), then
call the slice concat `0x3bc5ae0` with two parts.

| builder (FDE) | body | bytes |
| --- | --- | --- |
| `0x37d0e60..0x37d0fa1` | allocates 20 (`0x37d0eb9`), copies from the argument | account |
| `0x37d0b40..0x37d0d15` | allocates 52 (`0x37d0bad`), copies 20 from `arg+0x20`, then reverses `arg+0x00..0x20` into body `+0x14..+0x34` | storage |
| `0x37d0d20..0x37d0e5f` | allocates 32 (`0x37d0d79`), copies from the argument | code |
| `0x2811750..0x28118bc` | allocates 8 (`0x28117ee`), `bswap r14` at `0x2811801`, concat `0x254dab0` | height |

The slot reversal is not read by eye. `run_sse` evaluates the actual instruction bytes
`0x37d0bdd..0x37d0c53` (punpck, pshufd, pshuflw, pshufhw, packuswb) and any other encoding fails
closed. The same evaluator runs `0x38036e2..0x380374b` for the U256 value path. Both produce the
exact reverse of the 32 input bytes.

### The prefix is the database label

Wrapper `0x358cea0` indexes the 28-row table at `0x56f1920` by code (`0x358cf80`, `0x358cf87`),
allocates 2 bytes, copies the 2 label bytes, and builds capacity 2, pointer, length 2 at
local `+0x10..+0x28` and the code byte at local `+0x30`. It stores those at `out+0x20` and
`out+0x40` (`0x358d15f..0x358d176`). The writers read the code at `wrapper+0x40` and pass
`wrapper+0x20` as the key `self`, so `self+0x8`/`self+0x10` are the label pointer and length.

### Binding code to table

`0x3269ae0` builds each wrapper with an immediate code, and passes `wrapper+0x20` to a function
whose body calls the same decoder as one getter:

| code | label | wrapper | wrapper+0x20 passed to | decoder call | decoder | getter |
| --- | --- | --- | --- | --- | --- | --- |
| 0x18 | `Ea` | `0x358cea0` | `0x37d3070` | `0x37d334c` | `0x2c641d0` | `0x37d0fb0` |
| 0x19 | `Ec` | `0x358d720` | `0x37d3bd0` | `0x37d3ec5` | `0x2a6afe0` | `0x37d13c0` |
| 0x1a | `Es` | `0x358d2e0` | `0x37d2550` | `0x37d281a` | `0x2ba6ab0` | `0x37d11d0` |

These three functions and `0x3269ae0` also appear in the digest evidence of #262 and #316, and the
writers below in the merged inventory `state-roots.json`. They are used here only as call edges;
none of those records states a key or value encoding.

### Read path

Six getters share one shape: build the key, test `home+0x10` against `i64::MIN` (no database, so
`None`), raw get, then decode. Each initializes one reader with the 17 fixed bytes at the sites in
the JSON (byte `+0x20` = 1, word `+0x22` = 0x400, byte `+0x24` = 0) and drops decode errors with the
compare chain 2, 5, 6. That reader byte pattern has 8 sites in `.text`; 6 are these getters,
`0x37d4b75` is in `0x37d47c0`, and `0x432fe8c` is out of scope.

The raw gets `0x3c98220` and `0x255a8e0` both call through slot `0x5774600` (RELATIVE target
`0x4f94810`) with five register arguments: handle, read options, key pointer, key length, error
slot. There is no column family argument.

### Write path

| writer | key call | value encoder | named-mode callee | batch put call | commit call |
| --- | --- | --- | --- | --- | --- |
| `0x37d15e0` | `0x37d182f` | `0x358ca80` | `0x326cfc0` | `0x37d18f7` | `0x37d19eb` |
| `0x37d1b20` | `0x37d1d50` | `0x358cc90` | `0x3804a40` | `0x37d1e2c` | `0x37d1f19` |
| `0x37d2000` | `0x37d2253` | `0x358c870` | `0x3bf8bb0` | `0x37d2320` | `0x37d2416` |

Each encoder takes the code byte from `wrapper+0x40`, then `add sil, 0xe9; cmp sil, 4; jae`. Codes
23..26 (`Eb`, `Ea`, `Ec`, `Es`) store `0x01000400` at serializer `+0x8`; every other code stores
`0x00000400`. So byte `+0xb` is 1 only for those four. The first store pattern has exactly 3 sites
in `.text`, all in these encoders.

`0x326cfc0` uses that byte. When it is nonzero, the value header comes from `0x35981d0` (fixmap base
`0x80`) and a one-byte name precedes each field. When it is zero the header comes from `0x3598e20`
(fixarray base `0x90`) and names are skipped. Field count and omission use the same compares in both
arms. Byte `+0xa` is 0 in both stores, which selects the binary branches at `0x3804a54` and
`0x3583bbb` over their `0x`-hex branches.

The `c` compare has two forms, the rodata constants `0x206160`/`0x204be0` and the immediates at
`0x326d141..0x326d15f`. The tool requires both to give the same 32 bytes, and the test recomputes
them as `keccak256("")` with a local Keccak.

### Differences from the reference

- `block_reader.rs` marks big-endian heights as `[INFERENCE]`. `bswap` at `0x2811801` confirms it.
- `block_reader.rs` has `HEIGHT_KEY_LEN = 8` and a column family selector. The binary concatenates a
  prefix before the height, and the raw get has no column family argument.
- `decode_stored_client_block` splits raw bytes at offset 32. The binary passes the stored bytes to
  the reader above and copies 0x398 decoded bytes out, so 0x398 is a decoded size here, not a
  stored record length.

### Concat census

`key-concat-sites.tsv` lists every direct call to both concat copies: 20 to `0x3bc5ae0`, 7 to
`0x254dab0`. The tool fails on any owner it has no role for. Five owners stay unresolved and are
not claimed to be database keys: `0x3284ad0`, `0x3284c70`, `0x3284d90`, `0x3330900`, `0x3362fd0`.

## Implementation and comparison

not yet implemented. There is no Rust path and no comparison against a real database; the model
functions in the tool are evidence checks, not an implementation.

## Results and limitations

- Tests: 30 in `tests/test_evm_kv_schema.py`, all pass. Negative controls change every rip pin's
  opcode and target, the last byte of every byte pin, the shuffle selectors, the store offsets, the
  gate, the flag, the code immediates and the hash immediates, and test a wrong digest, NOBITS and
  unmapped addresses, and an unclassified concat owner.
- The bin8 form of the 32-byte fields follows from the `0xc4` base in `0x35990f0` and the length 32;
  the model assumes that branch.
- rmp-serde is inferred from the Location strings `rmp-serde-1.3.0/src/encode.rs` and `decode.rs` in
  `.rodata`, the marker constants, the 0x400 word and the 2, 5, 6 error drop. No Location is tied to
  these functions here.
- The array arm for codes outside 23..26 exists in the encoders, but no code other than `Ea`, `Ec`,
  `Es` was shown to reach them.
- This is a static reading. No database file was inspected, and no gate is requested.

Next question: which code do the height getter `0x2810fb0` and the hash getters `0x2811160` and
`0x2811460` use, and what is the wire form of `Bytecode` in `0x3bf8bb0`?
