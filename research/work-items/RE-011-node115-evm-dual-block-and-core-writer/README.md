# RE-011: Node #115 HyperEVM Dual-Block Gas Limits, System Contracts & `CoreWriter` v1 Dispatcher

- **Component ID**: `evm` (Stream F, `RE-011`)
- **Target Artifact**: `artifacts/node/115/hl-node` (Linux x86-64 ELF, 105,896,032 bytes)
- **Target SHA-256**: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- **Crate Extended**: `src/evm/` (`src/evm/src/system.rs`, zero `Cargo.toml`/`Cargo.lock` changes)
- **Claim Status**: All ELF virtual addresses, immediates, jump-table entries, embedded contract byte slices, SHA-256 digests, and FDE bounds are **static observations** from the authenticated node #115 ELF (never executed). No acceptance gate is modified by this packet.

## Observations

### 1. Exact Dual-Block Gas Limits & Builder Cadence (`0x433dc40`, `0x2a1dd50`, `0x2c71eb0`)

- **Gas limits**: Both `0x433dd2b..0x433dd3d` (block execution in `0x433dc40..0x433e79c`) and `0x2a1e377..0x2a1e38f` (user `using_big_blocks` check in `0x2a1dd50..0x2a1eb71`) select between:
  - Small block gas limit: **`3_000_000`** (`0x2dc6c0`, `mov ecx, 0x2dc6c0`)
  - Big block gas limit: **`30_000_000`** (`0x1c9c380`, `mov eax, 0x1c9c380; cmovne rcx, rax`)
- **Block builder dispatch (`0x2c71eb0..0x2c74a69`)**:
  - Small block: label `build_small_evm_block_and_apply_l1_effects` (`0x60ea04`, 42 B), bucket-guard `f64` pair `(0.03, 0.07)` at `0x4554f0`, calls `0x2c71250(self, is_big=0)` at `0x2c72050`.
  - Big block: label `build_big_evm_block_and_apply_l1_effects` (`0x60ea2e`, 40 B), bucket-guard `f64` pair `(0.05, 0.05)` at `0x453520`, calls `0x2c71250(self, is_big=1)` at `0x2c72560`.

### 2. Three Embedded HyperEVM System Contracts (`0x434bda0..0x434cfe6`)

`0x434bdbf..0x434be01` installs three embedded runtime bytecodes via `0x434d2c0` from `.data.rel.ro`/`.data` descriptors `0x64fd8f8`, `0x64fd918`, and `0x64fd938`:

| System Contract | Address | `.rodata` Address VA | Bytecode VA | Bytecode Len | Bytecode SHA-256 |
|---|---|---:|---:|---:|---|
| `CoreWriter` | `0x3333...3333` | `0x7cab27` | `0x7a08f9` | 544 B | `fd053fae53aa5ff797c8de9d38f5180d3c280228ae2d669ef9a83ab7834dac83` |
| `HypeSystem` | `0x2222...2222` | `0x7caac9` | `0x7a0b31` | 122 B | `89c9f51d82a9ec4b4f386d157c477ac7e396bff125e461f691be57bc5d2f816a` |
| `WHype` | `0x5555...5555` | `0x7cab3b` | `0x7a0be5` | 2,041 B | `f7d3c155f5cbc8c04736f97f628e0547f2c7cd6d7bc38acfaf74d7e975f81d6b` |

### 3. `CoreWriter` v1 `RawAction(address,bytes)` Frame Parser (`0x38bf120..0x38c044c`)

- Event signature `RawAction(address,bytes)` at `0x7a0b19` (referenced at `0x38bff37`); HYPE deposit event `Received(address,uint256)` at `0x7a0bab` (referenced in `0x3897560..0x389775e`).
- Length & header validation (`0x38bf48a..0x38bf531`):
  1. `1 <= raw.len() <= 1000` (`sub rdi, 0x3e9; cmp rdi, -0x3e8; jb 0x38c0332`)
  2. `raw.len() >= 4` (`lea r12, [r13 - 4]; cmp r12, -3; jae 0x38bf65d`)
  3. Header decode: `version = raw[0]`, `action_id = u24_be(raw[1..4])` (`bswap rbx; shr rbx, 0x28`)
  4. `disabled_core_writer_actions` check via `0x35be2f0` (`0x38bf4e5..0x38bf502`)
  5. `version == 1` (`0x38bf508: cmp r13b, 1`)
  6. 17-entry jump table `0x79e340` (`dec rbx; cmp rbx, 0x10; ja 0x38c0323`): action IDs `1..=13` and `15..=17` dispatch to dedicated ABI decoders, while slot `13` (`action_id == 14`) jumps directly to reject (`0x38c0323`).

### 4. Read Precompile Input ABI Decoder Families (`0x0800..=0x0814`)

All 21 HyperEVM read precompile callbacks (`0x38df640..0x38ea5b4`) classify into 5 observed prologue decoder families:
- Empty (no decoder call): `0x0809`
- `0x3896ec0` (348 B, 1-word uint/index): `0x0806`, `0x0807`, `0x0808`, `0x080a`, `0x080b`, `0x080c`, `0x080d`, `0x080e`, `0x0814`
- `0x3897020` (469 B, 2-word `(address, uint)`): `0x0801`, `0x0811`
- `0x3897200` (318 B, 1-word): `0x0812`
- `0x38f9750` (213 B, generic `ethabi::decode`): `0x0800`, `0x0802`, `0x0803`, `0x0804`, `0x0805`, `0x080f`, `0x0810`, `0x0813`

## Remaining Unknowns

- Individual Rust ABI struct field layouts for each of the 16 active `CoreWriter` action decoders (`0x38d3490..0x38d7ba0`) and the 20 non-`0x0809` read precompile query bodies remain open for future slices.

## Reproduce

```sh
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 cargo test --offline --locked --manifest-path src/evm/Cargo.toml
CARGO_BUILD_JOBS=4 cargo clippy --offline --locked --manifest-path src/evm/Cargo.toml --all-targets -- -D warnings
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_evm_dual_block_and_core_writer_115 -v
PYTHONDONTWRITEBYTECODE=1 python3 tools/verify_packets.py research/work-items/RE-011-node115-evm-dual-block-and-core-writer
```
