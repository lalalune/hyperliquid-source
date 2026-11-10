# RE-005-node115-vault-address-derivation: which bytes does node #115 hash to name a new vault, and which 20 does it keep?

With this packet the 20-byte address that node #115 derives for a `createVault` request (creator, name, description,
`initialUsd`, `nonce`) can be computed without the binary, and the two limits the analysed caller applies around that
derivation (name length, amount bound) can be reproduced. Before it, the repository documented the generic
MessagePack writers, the Keccak sponge and the action's wire name and result variant, but nothing that says what a
vault creation feeds into the hash: the creator as a `"0x"` hex string, the four-field named map, that the request's
`maxUsdcFee` is left out of the hash, which digest bytes are kept, and which of the caller's checks happen before or
after the address exists. The Rust crate [`src/node115-vault-address`](../../../src/node115-vault-address/README.md)
implements it; 135 corpus cases written before the crate existed (`ORACLE_FROZEN.txt`) agree with it. It does **not**
create a vault or change any state: it stops where the caller hands the address on.

**Read this first.** (1) Static reconstruction only: the binary was never executed or emulated, and no behavioural
equivalence with the node is claimed. (2) The result `ok` (corpus column `caller_outcome`, Rust `caller_address` returning
`Ok`) only means "passed this caller's name-length and amount checks"; it is **not** "the vault was created". (3) The role
names (`creator`, the request fields, "vault address") and the business meaning of the returned 20 bytes are inferences
from key literals, offsets and position; what the dispatcher's 20 creator bytes are (the action's signing user?) was not
traced. (4) The model covers strings shorter than 2^32 bytes and assumes no allocation failure and no unwind. (5) The new
Rust tests are not collected by `make test`; they are run by the manual commands under Reproduce.

- Component ID: `vaults` (inferred: the `createVault` action; the digest wrapper carries the `l1/src/utils.rs:19:42` Location, see RE-001 below)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked before anything else; the tools refuse any other file)
- Source commit / reference commit: main `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference source consulted
- Claim status: observations are pinned bytes, decoded instructions, FDE ranges, relocation slots and call-site scans (`pins.json`); the data-flow reading, the names of roles and the model are inferences by one reader; semantic equivalence with the running node is unresolved (the binary is never executed or emulated)
- Scope included: creator + request -> preimage -> Keccak-256 -> first 20 bytes (entry `0x46dba10`); the caller's name limit and amount bound (`0x2bdd3b0`); the wrapper's mapping of the result word. Excluded: everything the caller does after its checks, the other two same-shaped callers, vault creation and state, allocation failure and unwind, the optional-field sub-writer `0x471aea0`

## Credit: what already existed and what is new

| Prior work in the tree | What it already established | Use here |
| --- | --- | --- |
| `RE-010-action-serialize-tag-dispatch-115` | `CreateVault` is action variant 7, wire name `createVault`, first word `0x8d`; the per-copy payload serializers (not this entry) | context |
| `RE-010-display-name-path-115` (`switches.tsv`, `switch-tables.tsv`) | the dispatcher switch rows for variant 7 / `0x8d` / `createVault` list `0x2bdc248` among their addresses | the arm is re-pinned in one window (what it passes on is read here); the address is **not new** |
| `RE-017-abci-res-variants-115` | `createVault` is result variant 2, payload "address of input +1", hex output width 42 for 20 bytes through slot `0x64e4d08` | credited; the wrapper's tag 2 + 20 bytes at +1 is re-pinned (`wrapper_call_and_success`) |
| `RE-001-node115-utils-serialization-digest` | the same 517-byte shape one function earlier (`0x38d2ce0`): serialize into a vector, check head `0x8000000000000004`, hash, return 32 bytes | the entry `0x38d2ef0` is its sibling by size and structure; its role (hashing the `createVault` pair) is new |
| `RE-001-node115-loc-edge-38d308f` | `0x38d2ef0` FDE, the unwrap-on-`Err` Location edge at `0x38d308f` (`l1/utils.rs`, line 19, column 42) | credited; the failure window is re-pinned, **not new** |
| `evm-keccak-ripemd-hash-115` | Keccak-f `0x5cda380`, sponge write `0x5cda910`, pad-and-read `0x5cdad40` rebuilt in Python | credited, not re-derived; the two slots re-pinned; the incremental Rust form is new code only |
| `src/node115-sponge-permutation`, `RE-009-sponge-permutation-115` | MIT permutation over 25 lanes | **path dependency, unchanged** |
| `src/node115-noop-preimage`, `RE-001-node115-noop-preimage` | one-block absorb for a short preimage; fixstr via `0x3d52310`; string writer `0x41c6110` | adapter pattern; the multi-block form is generic here |
| `RE-015-rmp-write-uint-b-115` | unsigned writer `0x3d517e0` and width helpers: fixint / `cc` / `cd` / `ce` / `cf` | credited; thresholds re-pinned, **not new** |
| `evm-tx-rmp-struct-serializers-115`, `vaults-struct-serializers-115`, `serialization-rmp-newtype-forward-115` | writer byte `+0xb` (0 array, nonzero map, exactly 1 names), header writers `0x3d50270` / `0x3d4f6d0`, compound end `0x41d3f60` | same convention found in `0x46c9450` / `0x41d4c70`; credited |
| `RE-017-abci-root-tree-115` | unsigned adapter, array header widths, the sentinel fast path of the compound end | credited; windows re-pinned |
| `RE-002-node115-vendor-census`, `research/byte-windows.json`, `RE-002-node115-rust-impl-serde-hex-bindings` | `0x2eabb50` is `impl-serde` `to_hex_raw`, `0x5cda380` is `tiny-keccak` `keccakf` | boundaries, no credit claimed; the other 19 pinned FDEs overlap no public window (`public-overlap.tsv`, regenerated by the verifier) |

**New here:** (1) the entry `0x46dba10`: what it copies from the request, that it stores option tag 0 in the copy it serializes, the 20-byte result and the result word `0x1a2`; (2) the pair serializer `0x41d4c70` as used by this entry (creator as direct string, request map) and its sole role as feeder of `0x38d2ef0`; (3) the creator text writer `0x41d3a50` (direct path, 42 characters from 20 bytes); (4) the request map `0x46c9450`: key literals, order, source offsets, the conditional fifth field; (5) the caller `0x2bdd3b0` checks (state gate, name limit before the call, amount bounds after it) and the request layout common to wrapper, entry and caller; (6) the Rust API, the frozen oracle with 1,428 wrong-variant addresses, and the pin / verify / mutation tools. The generic writers are re-pinned because their byte widths are the contract; they are prior work.

## Reproduce

From the repository root. Python 3.12.3, the Python `capstone` module 4.0.2 (first decoder), GNU objdump 2.42 (second decoder), cargo/rustc 1.99.1 (the repository pins 1.95.0, not available here). `work/` is the ignored scratch directory; every tool takes a **new** `--outdir` (refused if it exists or lies inside this packet or the crate) and never writes elsewhere. The ELF must be the materialised LFS object at `artifacts/node/115/hl-node`; `--elf` overrides the path. Nothing is executed or emulated, no network.

```sh
P=research/work-items/RE-005-node115-vault-address-derivation
python3 -I $P/gen_oracle.py --selftest
python3 -I $P/gen_oracle.py --outdir work/vault-address-oracle
cmp work/vault-address-oracle/corpus.tsv $P/corpus.tsv
cmp work/vault-address-oracle/wrong-variants.tsv $P/wrong-variants.tsv
python3 -I $P/verify_target.py --outdir work/vault-address-verify --with-objdump --public-overlap
python3 -I $P/verify_target.py --outdir work/vault-address-pins --regen-pins $P/pin_spec.json
cmp work/vault-address-pins/pins.json $P/pins.json
python3 -I $P/verify_target.py --outdir work/vault-address-selftest --selftest
cargo test --offline --locked --manifest-path src/node115-vault-address/Cargo.toml --target-dir work/vault-address-target
cargo test --release --offline --locked --manifest-path src/node115-vault-address/Cargo.toml --target-dir work/vault-address-target-release
python3 -I $P/mutate.py --outdir work/vault-address-mutselftest --selftest
python3 -I $P/mutate.py --outdir work/vault-address-mutants
sha256sum -c $P/MANIFEST.sha256
```

Expected: oracle selftest ok; the two `cmp` silent; verify prints `failures: 0` (and `fdes_with_overlap: 2`); the regenerated pins are identical; the selftest prints the controls listed below; 10 tests pass (1 unit, 9 integration) in both profiles; the mutation run ends `39 mutants, 39 killed by their named test, 0 not`. `make verify`, `make test`, `make catalogue-check` and `make reproduce` were **not** run (see Limits), and `make test` would not collect the Rust tests anyway (it runs only the Python files under `tests/`), so none of the commands above is part of a `make` target. Exit codes of the tools: 0 pass, 1 check failed / mutant survived, 2 environment error.

I ran the commands above, in this order, in a fresh `git worktree` of main `a8616af94` with only the new files added (the ELF through `--elf`, because that worktree holds the LFS pointer; the commands were given absolute paths because my shell could not change into the worktree): oracle selftest ok; the two `cmp` silent (135 cases, 1,428 wrong addresses); `verify_target.py` with objdump `failures: 0` (21 FDEs, 4 relocation slots, 6 strings, 8 cross-reference targets, 45 windows / 427 instructions, 7 derived facts, 2 FDEs overlapping the public registries); regenerated `pins.json` identical; both selftests as described below; 10 Rust tests in the debug and in the release profile; 39 of 39 mutants. `sha256sum -c` was not run (it needs the repository root as working directory); the same digest comparison was done with a small script outside the tree: 16 entries, 0 mismatches. `git status` listed only the two new directories, with no tracked file modified. After the wording and test-name revision (doc comments, READMEs and one test rename; no code change) I repeated the debug and release tests (10 each), the oracle selftest and regeneration with both `cmp`, `verify_target.py` with objdump and public overlap (same counts, `failures: 0`) and the 39 mutants (39 killed) in a second fresh worktree; the pin regeneration and the two selftests were not repeated (their inputs are unchanged). The manifest covers the packet (without itself) and the crate files, `Cargo.lock` included.

## Evidence

Addresses are linked virtual addresses; FDE ends are exclusive. Rows cite pins in `pins.json` (names in brackets); the author's claim text sits next to the decoded bytes there. Anything marked "not pinned" was read by the author only.

### The flow

| Step | Where | Observation |
| --- | --- | --- |
| dispatcher arm | `0x2bdc248..0x2bdc270` | 20 bytes copied from `r13` as the creator, the action payload is `r12+8`; call `0x283b2e0` [`arm_createvault`] |
| wrapper | `0x283b2e0` (421 B) | clones name and description, copies request `+0` (16 bytes) and `+0x40` (16 bytes) into a new record, calls the caller; result word `0x1a2` -> output tag 2 and the 20 address bytes at output `+1`; any other word -> output tag `0xf` with the error record [`wrapper_request_copy`, `wrapper_call_and_success`]. Two direct call sites: `0x2bdc26b` (the arm) and `0x2c0dd9d` (not examined) |
| caller | `0x2bdd3b0` (1,794 B) | state field `+0x7d0` zero -> panic path [`caller_state_gate`]; name length at request `+0x20`: `>= 0x65` frees the copy and returns tag `0x158` with the string record, before anything is hashed [`caller_name_limit`]; calls slot `0x64e7878` with creator and request [`caller_derive_call`]; on word `0x1a2` keeps the 20 bytes and compares `initialUsd` (`+0x40`) and, when the byte at `+0` is nonzero, `maxUsdcFee` (`+8`) with `0x0ccccccccccccccc` (`>=` -> tag `0x154` with the value; absent fee counts as 0) [`caller_amount_bounds`, `caller_amount_absent_fee`]. The slot `0x64e7878` (RELATIVE to `0x46dba10`) has three call sites: `0x2bdd46e` (this body) and `0x54a465e`, `0x54a4d6e` (same-shaped neighbours, only the first instructions around the call and the `0x158` store were looked at) [`slot_entry`, `entry_46dba10`] |
| entry | `0x46dba10` (399 B) | clones name (`+0x18/+0x20`) and description (`+0x30/+0x38`); builds a record with the creator (20 bytes) and the request copy: **option tag stored as 0** at `[rsp+0x28]`, the original `+8` copied but not used, the 16 bytes at `+0x40` copied; the request's `+0` is never read (derived: displacements `0x8, 0x18, 0x20, 0x30, 0x38, 0x40` only, `rbp` written once) [`entry_*`, `entry_request_reads`]; calls `0x38d2ef0`; copies the first 20 of the 32 result bytes to output `+2`, word `0x1a2` at `+0` [`entry_result`]; allocation failure -> slot `0x64df498` and `ud2` |
| digest | `0x38d2ef0` (517 B) | empty vector, calls `0x41d4c70`; only head `0x8000000000000004` continues; zeroed 200-byte state, rate `0x88`, delimiter byte 1; update through slot `0x64e0148` with the whole buffer, 224-byte copy, finalize 32 bytes through slot `0x64e0150`; returns all 32; serializer failure -> unwrap-on-`Err` panic [`digest_*`] |
| pair serializer | `0x41d4c70` (574 B) | writer byte `+0xb` = 1 (flag dword `0x1000400`); array header count 2; creator through `0x41d3a50` with the sentinel buffer (direct path, no buffered-bytes flush); request = pair `+0x18` through `0x46c9450`; compound end `0x41d3f60` [`pair_*`] |
| creator text | `0x41d3a50` (357 B) | sentinel capacity -> direct path; slot `0x64e4d08` (`to_hex_raw`) with a 42-byte buffer, 20 input bytes, `skip_leading_zero` 0; the string is written by `0x41c6110`. `to_hex_raw` stores `"0x"` and takes digits from the table `0x455d40` = `0123456789abcdef` [`hex_direct_gate`, `hex_format_and_write`, `hex_prefix_0x`, `hex_first_digit`, `hex_digits`] |
| request map | `0x46c9450` (488 B) | count 4 when the option tag at `+0` is 0 (5 otherwise); named map; keys `name`, `description`, `initialUsd`, `nonce` from `0x45a108`, `0x7da3bd`, `0x7da3c8`, `0x7da3d2`, values: string `+0x18/+0x20`, string `+0x30/+0x38`, unsigned `+0x40`, unsigned `+0x48`; if the tag is nonzero, key `maxUsdcFee` (`0x7da3d7`) and value `+8` through `0x471aea0` [`map_header_count`, `field_*`, `key_*`] |
| consumers | byte scan of `.text` for `call`/`jmp rel32` plus `.rela.dyn` RELATIVE slots and `call [rip+slot]` | `0x38d2ef0`, `0x41d4c70`, `0x46c9450` each have exactly one direct call site (`0x46dbaf6`, `0x38d2f2c`, `0x41d4dbc`) and no slot; `0x41d3a50` has two (`0x41d48fd`, `0x41d4cf7`); `0x471aea0` has three (`0x46b1c4e`, `0x46c8c46`, `0x46c95ea`); `0x2bdd3b0` has one (`0x283b3ba`). Within this scan, the digest wrapper, the pair serializer and the request map have no consumer other than this entry [`xrefs`] |

### Bytes of the preimage

`92 | d9 2a "0x" + 40 lower-case hex digits | 84 | a4 "name" | str(name) | ab "description" | str(description) | aa "initialUsd" | uint(initialUsd) | a5 "nonce" | uint(nonce)`

* strings (`0x41c6110`, 32-bit length tests): length <32 -> `a0|len`; <256 -> `d9 len`; <65536 -> `da` + 2 bytes big-endian; else `db` + 4 bytes; payload copied verbatim [`str_*`, `marker_fixstr`]
* unsigned (`0x3d517e0`): <128 raw byte; <256 `cc`; <65536 `cd` + 2; <2^32 `ce` + 4; else `cf` + 8, all big-endian [`uint_*`]
* headers: count <16 -> `0x90|n` / `0x80|n` [`array_header_select`, `map_header_select`]
* digest: Keccak-256 (rate 136, delimiter `0x01`, `0x80` at rate-1), the first 20 of 32 bytes

Anchor, recorded by the scout with Node/OpenSSL and reproduced by the oracle (not re-run here): creator `00`x20, `v`, ``, 1, 2 -> 85 bytes -> digest `91378d26...676c` -> address `91378d2649be144c8abfa4d4b7626d5413ceb45e`.

### Differences from a standard reading (the bytes win)

| Where a standard reading could go wrong | What #115 does |
| --- | --- |
| creator as 20 raw bytes / `bin` / array of numbers | a MessagePack **string** of 42 characters, `0x` + lower-case hex (`d9 2a` header) |
| the whole request as hashed input | four fields; `maxUsdcFee` is not hashed whether absent, zero or maximal: the entry sets the option tag of its copy to 0 |
| SHA3-256 vs Keccak-256 | delimiter byte 1 -> Keccak; SHA3 padding would give different addresses (a wrong variant in the corpus) |
| struct as array vs map | named map (`+0xb` is 1) in the order `name`, `description`, `initialUsd`, `nonce` |
| which digest bytes | the first 20, not the last 20 or all 32 |
| huge strings | length tests are 32-bit; strings of 2^32 bytes or more are **not** modelled (`Error::StringTooLong`) |
| what the caller lets through | name length <= 100 (the modelled entry applies no name limit; strings of 2^32 bytes or more, allocation failure and unwind are not modelled); `initialUsd` and `maxUsdcFee` below `floor(2^64 / 20)`, i.e. `0x0ccccccccccccccc` and up are rejected *after* the address was derived; `nonce` is not bounded in this caller |

### Public dependency check

`RE-002-node115-vendor-census/census.json` (7,574 records) and `research/byte-windows.json` (7,887 windows) were compared with the 21 pinned FDEs by `verify_target.py --public-overlap` (output `public-overlap.tsv`). Only `0x2eabb50..0x2eabcde` (`impl-serde` `to_hex_raw`) and `0x5cda380..0x5cda902` (`tiny-keccak` `keccakf`) overlap; both are boundaries and reused, not counted. The flow functions `0x46dba10`, `0x38d2ef0`, `0x41d4c70`, `0x41d3a50`, `0x46c9450`, `0x2bdd3b0`, `0x283b2e0` and the writers overlap nothing (this includes the sponge update/finalize bodies `0x5cda910` / `0x5cdad40`, which the registry does not list). A non-match is not proof of origin.

### Inferences (not observations)

* the role names creator, request fields and vault address: the keys are the literals above; "creator" is how the scout and the pair position name the 20 bytes the arm copies from `r13`, and what `r13` is in the dispatcher (the action's signing user?) was not traced here
* the tags `0x1a2`, `0x158`, `0x154`, `0xf` and the output tag 2 are internal discriminants; their meaning beyond "success", "name rejected" and "amount rejected" was not recovered
* the byte at writer `+0xb` is set as part of the dword `0x1000400` by `0x41d4c93`; the other bytes of that dword (`+9` = 4) are not interpreted
* `0x5cda910` / `0x5cdad40` behave as the incremental Keccak the crate implements (credited to `evm-keccak-ripemd-hash-115`; windows re-pinned, bodies read by the author)
* what the caller does with the accepted address: between `0x2bdd5c3` and `0x2bdd9ac` it compares the 20 bytes with 20-byte keys in a ring/B-tree pair at state `+0xa18`, with 20 bytes at record offset `+0x80` of `0x510`-byte records at state `+0x7c8`, and passes it to slot `0x64e7880` with state `+0x80`; a hit returns tag `0x81`, `0x18` or `0x1e`, otherwise `0x2c3c800` is called (read quickly, **not pinned, not modelled**)

## Implementation and comparison

* `src/node115-vault-address`: `address_preimage`, `address_digest`, `derive_vault_address` (the entry), `caller_address` (entry + the two checks), `Keccak256` (absorb/finalize). No crates.io dependency, no root workspace; the permutation is the existing crate by path.
* Oracle (`gen_oracle.py`, frozen first, `ORACLE_FROZEN.txt`): a hand-written MessagePack encoder and a Keccak written from the specification recurrences (not copied tables, whole-message padding), checked on 3 published Keccak-256 vectors (empty input, `abc`, the quick-brown-fox sentence), on 702 lengths against `hashlib.sha3_256` with delimiter `0x06` (permutation, rate, multi-block, padding; delimiter `0x01` rests on the published vectors), on 20 byte-exact MessagePack examples and on the scout anchor; the caller's amount bound is recomputed as `floor(2^64 / 20)` and asserted equal to the constant read from the binary. It is not the Rust code and does not read it. It **is** the same author's reading of the bytes: agreement shows model consistency, not that the node produces these addresses.
* Corpus (135 cases): anchor; 21 `initialUsd` values and 22 `nonce` values around 127/128, 255/256, 65535/65536, 2^32-1/2^32, the caller's bound +-1, 2^63 and u64 max; 7 creators (hex letters, digits only, 0x80, 0xff...); 18 name lengths (0..2, 30..33, 99..102, 254..257, 65535..65537); 16 description lengths (1, 2, 30..33, 254..257, 4095, 65534..65537, 200,000; length 0 is the anchor); 6 UTF-8 names and 6 UTF-8 descriptions; 9 cases with preimage length 134-138 and 270-273 (around the rate multiples 136 and 272; the third multiple, 408, is not hit exactly); 7 rows of the caller's checks (name 100 and 101, name 101 with a bad amount, amounts at the bound, fee at bound-1 / bound / u64 max); 12 `maxUsdcFee` values for one request (absent, 0, 1, 127, 128, 255, 256, 65536, 2^32, bound-1, bound, u64 max) with a single address; one-field-changed pairs (creator last bit / first byte, name, description, `initialUsd`, `nonce`, name<->description and usd<->nonce swaps), all addresses distinct. `wrong-variants.tsv`: 1,428 addresses of thirteen wrong implementations, listed for the 126 cases whose preimage is at most 600 bytes (upper-case creator hex, no `0x`, creator as `bin8`, two map orders, `maxUsdcFee` always / when present, positional array instead of map, no outer array, no creator, last 20 digest bytes, SHA3 padding, fixed-width unsigned); the tests assert the crate never equals them; a further test (`request_map_keys_follow_the_order_extracted_from_the_binary`) parses the keys out of every short preimage the crate builds and compares them with the key order pinned from the ELF bytes (coincidences allowed only where they are mathematically forced: upper-case hex of a creator without letters, fixed width when both numbers need 8 bytes).
* Which corpus rows the real caller lets through is a column of the corpus (`caller_outcome`: 115 `ok`, 11 `name_too_long`, 9 `amount_too_large:<value>`) and a test input class: the rows with names above 100 bytes (and amounts or fees at or above the bound) are **entry-only** inputs; the entry derives an address for them, the caller does not let them through, and the tests named `caller_*` say which side they check. `ok` means only "passes the name limit and the amount bounds of this caller".
* Mutation (`mutate.py`): 39 source mutants (header counts, `0x` prefix, hex case, key text, value sources, the maxUsdcFee leak, every string/unsigned boundary and marker, endianness, digest window, the 32-bit string limit, name limit and its check, amount bound, `>`/`>=`, removed fee check, reported value, Keccak delimiter/rate/padding/block permutation/xor/offset/output window), each built and run separately in its own target directory; all 39 are killed by the test named for them. The first full run had one mutant (skipped block permutation) killed by a different test than the one named: the Keccak unit test compares the code with itself when chunking and its published vectors are shorter than a block, so only the corpus (preimages past 136 bytes) catches it; the expectation was corrected to the corpus test and the run repeated. `--selftest`: baseline first, then an equivalent edit **survives**, an uncompilable edit is `BUILD_ERROR` (not a kill), a missing cargo is exit 2, a real mutant is killed, and two flipped bits in the corpus are caught.
* Verification (`verify_target.py`): 21 FDEs (range from `.eh_frame_hdr` and the FDE itself, plus body hash), 4 relocation slots, 6 strings with the instruction that references each, 8 cross-reference targets (byte-pattern scan, not a disassembly: stray `E8`/`E9`/`FF15` byte runs and computed indirect calls are not excluded), seven facts derived mechanically from the decoded bytes instead of typed in (the set of request offsets the entry dereferences; the key literals of the request map in address order, read from the ELF at the `lea` targets: `name`, `description`, `initialUsd`, `nonce`, `maxUsdcFee`; and the ordered call sequences of the entry, digest wrapper, pair serializer, creator writer and request map, with slots resolved through `.rela.dyn`), and 45 windows (427 instructions) decoded by Capstone and **also** by GNU objdump, text identical (both read the same bytes; `[reg+0x0]` is normalised because objdump spells a zero displacement out). `--selftest`: baseline first; 15,216 single-bit flips of the pinned bytes are all rejected (14,774 also change the decoded text) and 19 other corruptions (pin text/address/FDE/relocation/cross-reference/string/derived read set, key order and call sequence/target hash, missing ELF, existing/in-packet/in-crate outdir) are rejected. This is an integrity check of the pins; it says nothing about what the instructions mean.

## Results and limitations

| Metric | Value |
| --- | --- |
| corpus cases / wrong addresses | 135 / 1,428, all agree / all differ |
| Rust tests | 10 pass (1 unit, 9 integration), debug and release profile, cargo 1.99.1 |
| mutants | 39 of 39 killed by their named test |
| pinned instructions | 427 in 45 windows, Capstone = objdump |
| FDEs / relocation slots / strings / cross-reference targets / derived facts | 21 / 4 / 6 / 8 / 7, 0 failures |

Limits, plainly: one reader produced the pins' claims, the oracle's expectations and the Rust, so a shared misreading would pass every check here; the independent parts are the standards (MessagePack, Keccak), the recomputed amount bound and the second decoder. The binary was not executed, so no address was observed from a running node. The model ends where the caller hands the address on: the probes and the creation call are not modelled, so "the vault exists" or "the creation succeeds" is **not** claimed for any corpus row, including `ok` ones. The state gate at `+0x7d0` (panic path) is not modelled. Two same-shaped callers (call sites `0x54a465e`, `0x54a4d6e`) and the wrapper's second call site (`0x2c0dd9d`) were not examined, so the name limit and the bounds are pinned for `0x2bdd3b0` only. This caller does not limit the description; whether a layer above it does is unknown, so the corpus' long descriptions are entry inputs and caller-prefix inputs, not known-reachable requests. The optional-field sub-writer `0x471aea0` (three call sites) was not decoded; the fifth field's value form is not pinned and the Rust has no fifth-field writer. Names and descriptions are valid UTF-8 `String`s in the model. Allocation failure, unwind and ABI are out of scope. `make verify`, `make test`, `make catalogue-check`, `make reproduce`, rustfmt, clippy and the pinned 1.95.0 toolchain were not run. No progress gate is requested.

Next question: what the caller does with the accepted address between `0x2bdd5c3` and `0x2bdd9ac` (the three probes keyed by the 20 bytes and the creation call `0x2c3c800`), whether the two same-shaped callers around `0x54a465e` / `0x54a4d6e` and the second wrapper call site `0x2c0dd9d` apply the same limits, and where the 20 creator bytes of the dispatcher arm come from.
