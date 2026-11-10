# RE-005-node115-token-id-derivation: which bytes does node #115 hash to make a token id, and which 16 does it keep?

With this packet the 16-byte token id that node #115 derives from a `TokenSpec` (name, `szDecimals`, `weiDecimals`)
and a token index can be computed without the binary, and the two checks that surround it in the registration
caller (index limit, duplicate id) can be reproduced. Before it, the repository documented the digest handoff
(`0x38d2ce0`) and the generic MessagePack writers, but nothing said what a token registration feeds into that hash,
which digest bytes it keeps, or how the kept bytes meet the duplicate check. The Rust crate
[`src/node115-token-id`](../../../src/node115-token-id/README.md) implements it; 104 corpus cases written before the crate existed (`ORACLE_FROZEN.txt`) agree with it. It does not
implement token registration, only the id and those two gates.

- Component ID: `exchange` (inferred: token registration under spot deploy; the digest utility carries the `l1/src/utils.rs:19:42` Location, see RE-001 below)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked before anything else; the tools refuse any other file)
- Source commit / reference commit: main `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference source consulted
- Claim status: observations are pinned bytes, decoded instructions, FDE ranges and relocation slots (`pins.json`); the data-flow reading, the names of roles and the model are inferences by one reader; semantic equivalence with the running node is unresolved (the binary is never executed or emulated)
- Scope included: `TokenSpec` + index -> preimage -> Keccak-256 -> first 16 bytes; index limit and duplicate-id test in the caller tail `0x3c48ec1..0x3c49000`. Excluded: every other gate of `0x3c48b40`, token records, the native container layouts, allocation failure and unwind, the callers of `0x3c48b40`

## Credit: what already existed and what is new

| Prior work in the tree | What it already established | Use here |
| --- | --- | --- |
| `RE-001-node115-utils-serialization-digest` | `0x38d2ce0`: serialization result head `0x8000000000000004`, no suffix, 224-byte state copy, 32-byte result, `utils.rs:19:42` failure; input type left open | context; this packet supplies the input and the caller |
| `evm-keccak-ripemd-hash-115` | Keccak-f `0x5cda380`, sponge write `0x5cda910`, pad-and-read `0x5cdad40` rebuilt in Python and compared on 10,015 cases | credited, not re-derived; 5 windows and the 3 slots re-pinned; the incremental Rust form is new code only |
| `src/node115-sponge-permutation`, `RE-009-sponge-permutation-115` | MIT Rust permutation over 25 lanes | **path dependency, unchanged** |
| `src/node115-noop-preimage`, `RE-001-node115-noop-preimage` | one-block absorb for a <=49-byte preimage; fixstr via `0x3d52310`; string writer `0x41c6110` | adapter pattern copied; multi-block generalisation here |
| `RE-015-rmp-write-uint-b-115` | `0x3d517e0` and width helpers `0x3d51d10`, `0x3d51f40`, `0x3d520d0`: forms fixint/`cc`/`cd`/`ce`/`cf`, growth rules of `0x43bd910/0x43bd550` | credited; width windows re-pinned, **not new**; growth and allocation not modelled |
| `evm-tx-rmp-struct-serializers-115`, `vaults-struct-serializers-115`, `serialization-rmp-newtype-forward-115` | writer byte `+0xb`: 0 -> array header (`0x3d50270`), nonzero -> map header (`0x3d4f6d0`), exactly 1 -> field names written; compound end `0x41d3f60` | same convention found in `0x3c453f0`/`0x41d4b30`; credited |
| `RE-017-abci-root-tree-115` | unsigned adapter `0x41d2670`, array header widths | credited; windows re-pinned |
| `RE-002-node115-vendor-census`, `research/byte-windows.json` | `0x5cda380` is public `tiny-keccak` `keccakf` | the other 19 pinned FDEs overlap no public-library window (checked); `keccakf` is a boundary, no credit claimed |
| `staking-membership-request-115` | the 0x78-byte request layout handed to `0x3c48b40` (sink slot `0x64e7d08`), the **three request generators** `0x2c54de0`, `0x55c7640`, `0x55c78a0` (its only call sites, `callers.tsv`) and the **six callers of those generators** (`0x2c51f20`, `0x2c5cce0`, `0x55c19f0`, `0x55c1f80`, `0x55d6390`, `0x55d6720`); `0x3c48b40` named as an open sink | credited; this packet does not re-derive the request layout and reads only the sink's tail. The six are not callers of `0x3c48b40` |

**New here:** (1) `0x3c453f0`, the `TokenSpec` field writer: key names, order, source offsets, u8 widening;
(2) `0x41d4b30`, the pair serializer: array of two, spec then index, direct mode, and how `0x38d2ce0` is fed;
(3) the caller tail: index source, index gate, first-16-bytes take, 16-byte-keyed lookup, the two error strings;
(4) the Rust API and registry model, the frozen oracle with 703 wrong-variant ids, and the pin/verify/mutation tools.
The generic writers (`0x41c6110`, `0x3d517e0`, headers) are re-pinned because the byte widths are the contract; they
are prior work.

## Reproduce

From the repository root. Python 3.12.3, the Python `capstone` module 4.0.2 (first decoder), GNU objdump 2.42 (second decoder), cargo/rustc 1.99.1
(the repository pins 1.95.0, not available here). `work/` is the ignored scratch directory; every tool takes a **new** `--outdir`
(refused if it exists or lies inside this packet or the crate) and never writes elsewhere. The ELF must be the materialised
LFS object at `artifacts/node/115/hl-node`; `--elf` overrides the path. Nothing is executed or emulated, no network.

```sh
P=research/work-items/RE-005-node115-token-id-derivation
python3 $P/gen_oracle.py --selftest
python3 $P/gen_oracle.py --outdir work/token-id-oracle
cmp work/token-id-oracle/corpus.tsv $P/corpus.tsv
cmp work/token-id-oracle/wrong-variants.tsv $P/wrong-variants.tsv
python3 $P/verify_target.py --outdir work/token-id-verify --with-objdump
python3 $P/verify_target.py --outdir work/token-id-pins --regen-pins $P/pin_spec.json
cmp work/token-id-pins/pins.json $P/pins.json
python3 $P/verify_target.py --outdir work/token-id-selftest --selftest
cargo test --offline --locked --manifest-path src/node115-token-id/Cargo.toml --target-dir work/token-id-target
python3 $P/mutate.py --outdir work/token-id-mutselftest --selftest
python3 $P/mutate.py --outdir work/token-id-mutants
sha256sum -c $P/MANIFEST.sha256
```

Expected: oracle selftest ok; the two `cmp` silent; verify prints `failures: 0`; selftest prints the controls below; 9 tests pass (1 unit, 8 integration);
mutation run ends `29 mutants, 29 killed by their named test, 0 not`. `make verify` could not complete here (the worktree ELF is an LFS pointer),
`make catalogue-check`, `make test` and `make reproduce` were not run; `make test` would not collect the Rust tests anyway (it runs only the Python files under `tests/`),
so none of the commands above is part of a `make` target. Exit codes of the tools: 0 pass, 1 check failed / mutant survived, 2 environment error.

## Evidence

Addresses are linked virtual addresses; FDE ends are exclusive. Rows cite pins in `pins.json` (names in brackets); the author's claim text sits next to
the decoded bytes there. Anything marked "not pinned" was read by the author only.

### The flow

| Step | Where | Observation |
| --- | --- | --- |
| index source and gate | `0x3c48ec1`, `0x3c48f23..0x3c48f31` | index = state word `+0x28`; above `0x1869e` (99,998) the caller returns `too many tokens` (15 bytes, string `0x7bc148`) before any hashing [`caller_index_load`, `caller_index_gate`, `caller_index_error`] |
| build the pair | `0x3c48f70..0x3c48f91` | pair = (pointer to the 0x20-byte `TokenSpec` copy at `rsp+0x10`, index); calls `0x38d2ce0` [`caller_build_pair`] |
| digest entry | `0x38d2ce0` (517 B) | empty buffer, calls `0x41d4b30`; only result head `0x8000000000000004` continues; zeroed 200-byte state, offset 0, rate `0x88`, delimiter byte 1; update(buffer) via slot `0x64e0148`, finalize 32 bytes via slot `0x64e0150`; returns all 32 bytes [`entry_*`]. Slots are RELATIVE relocations to `0x5cda910` / `0x5cdad40` (checked in `.rela.dyn`) |
| pair serializer | `0x41d4b30` (305 B) | writer byte `+0xb` = 1; array header count 2; `TokenSpec` first (`0x3c453f0`), then the index through the unsigned adapter `0x41d2670`; direct mode (sentinel `0x8000000000000000`) [`pair_*`, `uadapter_*`, `finish_direct_*`] |
| spec fields | `0x3c453f0` (340 B) | map header count 3 (byte `+0xb` nonzero), keys `name` (4), `szDecimals` (10), `weiDecimals` (11) from `0x45a108`, `0x7bbf8f`, `0x7bbf99`, in that order; values: string at spec `+8/+0x10`, u8 at `+0x18`, u8 at `+0x19` zero-extended to the unsigned writer [`spec_*`] |
| keep 16 | `0x3c48f96` | the first 16 bytes of the returned digest are loaded as the id [`caller_take_16`] |
| duplicate test | `0x3c48fa8..0x3c48fdf`, `0x3cd39b0` | id passed to a 16-byte-keyed lookup comparing two byte-swapped qwords (byte-lexicographic order); result tag 1 returns `token_id already exists` (23 bytes, string `0x7bc131`, length stored at `0x3c48d0e`); otherwise the index goes to the vacant-insert function `0x3f19f10` [`caller_*`, `idcheck_*`] |
| consumers | byte scan of `.text` for `call`/`jmp rel32` plus `.rela.dyn` RELATIVE slots | `0x38d2ce0`, `0x41d4b30`, `0x3cd39b0`, `0x3f19f10` each have exactly one direct call site (`0x3c48f91`, `0x38d2d1c`, `0x3c48fbf`, `0x3c48ff1`) and no slot: within this scan the id derivation has no consumer other than this registration tail. `0x3c48b40` is reached only through slot `0x64e7d08`, whose three call sites are the request generators of `staking-membership-request-115` (`callers.tsv`; not re-scanned here). `0x3c453f0` has two more callers, in FDEs `0x3c44290..0x3c446c4` and `0x41b3000..0x41b30fe`, not examined [`xrefs`] |
| failure of the serializer | `0x38d2e32..0x38d2e93` | cleanup, then `Result::unwrap()` on `Err` at Location with file-name length 15, line 19, column 42 at `0x646e9c0` (`l1/src/utils.rs:19:42` per RE-001; the file pointer is a relocation; read by the author, not pinned) and `ud2`; the crate reports no value here |

### Bytes of the preimage

`92 | 83 | a4 "name" | str(name) | aa "szDecimals" | uint(sz) | ab "weiDecimals" | uint(wei) | uint(index)`

* strings (`0x41c6110`, 32-bit length tests): length <32 -> `a0|len`; <256 -> `d9 len`; <65536 -> `da` + 2 bytes big-endian; else `db` + 4 bytes; payload copied verbatim [`str_*`, `fixstr_combine`]
* unsigned (`0x3d517e0`): <128 raw byte; <256 `cc`; <65536 `cd` + 2; <2^32 `ce` + 4; else `cf` + 8, all big-endian [`uint_*`, `u16/u32/u64_*`]
* headers: count <16 -> `0x90|n` / `0x80|n` [`array_marker_select`, `map_marker_select`, `fixarray_combine`, `fixmap_combine`]
* digest: Keccak-256 (rate 136, delimiter `0x01`, `0x80` at rate-1), the first 16 of 32 bytes

Anchor, recorded by the scout with Node/OpenSSL and reproduced by the oracle (not re-run here): `X`, 6, 8, 0 ->
`9283a46e616d65a158aa737a446563696d616c7306ab776569446563696d616c730800` -> digest `9058f458...dd40` -> id `9058f4586f457c793b70c2871d15c2d5`.

### Differences from the standard (the bytes win)

| Where a standard reading could go wrong | What #115 does |
| --- | --- |
| SHA3-256 vs Keccak-256 | delimiter byte 1 -> Keccak (`0x38d2db9`); SHA3 padding would give different ids (a wrong variant in the corpus) |
| struct as array vs map | named map with string keys (`+0xb` is 1), key order `name`, `szDecimals`, `weiDecimals` |
| which digest bytes | first 16, not last 16 or all 32 |
| u8 decimals >= 128 | zero-extended: `cc xx`, never a signed int8 |
| huge names | length tests are 32-bit; names of 2^32 bytes or more are **not** modelled (`Error::NameTooLong`) |
| index range | the entry accepts any u64 (`cf` form), the caller only 0..=99,998 (so `cf` is not reachable through it) |

### Public dependency check

`RE-002-node115-vendor-census/census.json` (7,574 records) and `research/byte-windows.json` (7,887 windows) were
searched for overlap with the 20 pinned FDEs. Only `0x5cda380..0x5cda902` overlaps (`tiny-keccak` 2.0.2 `keccakf`); it is treated as
a boundary and reused, not counted. The flow functions `0x3c48b40`, `0x38d2ce0`, `0x41d4b30`, `0x3c453f0`, `0x3cd39b0` and the writers
overlap nothing. A non-match is not proof of origin.

### Inferences (not observations)

* the names TokenSpec/index/token id and the registration role, from the literals `name`, `szDecimals`, `weiDecimals`, the error strings and the
  caller's field offsets; the state word `+0x28` is "the index" only by how it is used
* the byte at writer `+0xb` is set by `0x41d4b4f` as part of the dword `0x1000400`; the rest of that dword is not interpreted
* `0x5cda910` / `0x5cdad40` behave as the incremental Keccak the crate implements (credited to `evm-keccak-ripemd-hash-115`; the windows are re-pinned, the bodies were read by the author)
* the B-tree branch of `0x3f19f10` was not traced; only key membership is modelled

## Implementation and comparison

* `src/node115-token-id`: `preimage`, `digest`, `token_id`, `Keccak256` (absorb/finalize), `TokenIds::register` (index gate, id, membership). No crates.io
  dependency, no root workspace; the permutation is the existing crate by path.
* Oracle (`gen_oracle.py`, frozen first, `ORACLE_FROZEN.txt`): a hand-written MessagePack encoder and a Keccak written from the specification recurrences (not
  copied tables, whole-message padding), checked on 3 published Keccak-256 vectors, on 702 lengths against `hashlib.sha3_256` with delimiter `0x06`
  (permutation, rate, multi-block, padding; delimiter `0x01` rests on the published vectors), on 17 byte-exact MessagePack examples and on the scout anchor.
  It is not the Rust code and does not read it. It **is** the same author's reading of the bytes: agreement shows model consistency, not that the node produces these ids.
* Corpus (104 cases): anchor; 20 index values (127/128, 255/256, 65535/65536, 2^32-1/2^32, 2^63, u64 max, 99,998/99,999); 42 decimals combinations (0, 1, 5, 6, 127, 128, 255);
  14 name lengths (0..2, 30..33, 254..257, 65535..65537); 6 UTF-8 names (multi-byte, NUL, 31/32 bytes with 16 characters); 13 cases with preimage length 134-138, 270-273,
  407-410 (around the rate multiples 136, 272, 408); 8 one-field-changed pairs, all ids distinct. `wrong-variants.tsv`: 703 ids of seven wrong implementations
  (map order, array order, spec map only with neither outer array nor index, map then index written back to back without the outer array, fixed 8-byte index, last 16 bytes, SHA3 padding); the tests assert the crate never equals them.
  The "map only" variant is the same id for every index by construction; the "map then index" variant is the one that keeps the index and drops only the `0x92` array header.
* Mutation (`mutate.py`): 29 source mutants (header counts, key text, field order and values, every string/unsigned boundary and marker, endianness, id window, name limit, Keccak delimiter/rate/padding/block permutation/xor/offset/output window, index gate, insert), each built and run
  separately in its own target directory; all 29 are killed by the test named for them. `--selftest`: baseline first, then an equivalent edit **survives**, an uncompilable edit is `BUILD_ERROR` (not a kill),
  a missing cargo is exit 2, and two flipped bits in the corpus are caught.
* Verification (`verify_target.py`): 20 FDEs (range from `.eh_frame_hdr` and the FDE itself, plus body hash), 3 relocation slots, 5 strings with the instruction that references each,
  7 cross-reference targets (byte-pattern scan, not a disassembly: stray `E8`/`E9` bytes and computed indirect calls are not excluded),
  68 windows (268 instructions) decoded by Capstone and **also** by GNU objdump, text identical. `--selftest`: baseline first; 9,472 single-bit flips of the pinned bytes are all rejected (9,199 also change the
  decoded text) and 16 other corruptions (pin text/address/FDE/relocation/cross-reference/string/target hash, missing ELF, existing/in-packet/in-crate outdir) are rejected. This is an integrity check of the pins; it says nothing about what the instructions mean.

## Results and limitations

| Metric | Value |
| --- | --- |
| corpus cases / wrong ids | 104 / 703, all agree / all differ |
| Rust tests | 9 pass (1 unit, 8 integration), debug and release profile, cargo 1.99.1 |
| mutants | 29 of 29 killed by their named test |
| pinned instructions | 268 in 68 windows, Capstone = objdump |
| FDEs / relocation slots / strings / cross-reference targets | 20 / 3 / 5 / 7, 0 failures |

Limits, plainly: one reader produced the pins' claims, the oracle's expectations and the Rust, so a shared misreading would pass every check here; the independent parts are the standards (MessagePack, Keccak) and the second decoder.
The binary was not executed, so no id was observed from a running node. Only key membership of the native container is modelled. The other gates of `0x3c48b40` are not modelled: their strings sit in the same function
(full-name length 1..50, fee share <=100%, existing-asset and duplicate-name checks, first/second token and deployer checks), and for a nonzero index the function also
requires `szDecimals <= 5` and `weiDecimals >= szDecimals + 5` (`0x3c48c4c..0x3c48c9b`, strings `szDecimals too large`, `weiDecimals must be at least szDecimals + 5`; read by the author, not pinned).
So the corpus deliberately includes decimals the caller would reject: the id function itself accepts any pair of u8 values. The registry tests cover only the two selected checks (index limit, duplicate id) and the order between them; they do not reproduce which registrations the caller accepts or rejects, and the inputs they use are chosen to pass the decimals check (the test file says so and asserts it). `0x3c48ecd..0x3c48f1e` holds a further early return before the limit (a call at `0x3c48f04`, string at `0x7bc106`) that is not analysed. Which (spec, index) sequences a real node feeds to the two checks is unknown (where the state word `+0x28` is incremented is the next question). The earlier draft's registry test used `AAA, sz=5, wei=8, index=1`, which the caller rejects at `0x3c48c7d` (`wei >= sz + 5` fails); it was replaced after the first review (see `ORACLE_FROZEN.txt` for the post-freeze amendment of the oracle files). Allocation failure, unwind and ABI are out of scope.
`make verify`, `make catalogue-check`, `make reproduce`, rustfmt, clippy and the pinned 1.95.0 toolchain were not run. No progress gate is requested.

Next question: what the three request generators (`0x2c54de0`, `0x55c7640`, `0x55c78a0`, the only call sites of the sink slot per `staking-membership-request-115`, which already documents the 0x78-byte request layout) and their six callers (`0x2c51f20`, `0x2c5cce0`, `0x55c19f0`, `0x55c1f80`, `0x55d6390`, `0x55d6720`) pass in the 0x78-byte request, and which of its fields the sink turns into the `TokenSpec`; where the state word `+0x28` is incremented, what the tree branch of `0x3f19f10` stores next to the id, and what the two other callers of the `TokenSpec` writer (`0x3c44290`, `0x41b3000`) do with it.
