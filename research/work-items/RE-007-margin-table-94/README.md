# RE-007: Margin Table & Tier Calculation Formulas (node #94)

- Component ID: RE-007 (Risk / Clearinghouse / Margin table formulas; `l1/clearinghouse/*`)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` (91,774,280 bytes)
- Source commit / reference commit: repository baseline `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference lead `references/can1357-hl/l1/clearinghouse/margin_table.rs`
  (unlicensed reference lead only; search guidance for mathematical formulas; zero implementation copied)
- Claim status:
  - Observation for the 3 exact FDE instruction sequences, opcode encodings, RELA relocation bindings,
    panic location line/column records, and `.rodata` source file path literal.
  - Inference for high-level struct field layouts, method roles, and clearinghouse solver lifecycle.
  - Unresolved items are listed in Results and Limitations.
- Scope included and excluded:
  - Included:
    - 3 exact FDE ranges:
      1. `0x3333580..0x333366e` (238 B, `max_leverage_for_position`, with fallback 50x = `0x32`)
      2. `0x3333670..0x33337f9` (393 B, `margin_after_tier_offset_div_6x_leverage`)
      3. `0x3333800..0x3333915` (277 B, `ntl_div_2x_leverage_minus_prior_contribution`)
    - 3 dynamic relocations in `.rela.dyn`:
      - `0x5775998` -> `0x3333580` (`max_leverage_for_position`)
      - `0x57759a0` -> `0x3333670` (`margin_after_tier_offset_div_6x_leverage`)
      - `0x57746e8` -> `0x3333800` (`ntl_div_2x_leverage_minus_prior_contribution`)
    - 2 `core::panic::Location` records in `.data.rel.ro`:
      - `0x56e9b40`: line 107, column 105 (referenced by error dispatch in `0x33337a9` and `0x3333906`)
      - `0x56e9b58`: line 101, column 57 (referenced by validation in `0x370c06f`)
    - Rodata source path literal: `/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/margin_table.rs` at VA `0x1fc39b` (65 bytes).
  - Excluded:
    - Zero execution of captured binary (static disassembly and offline arithmetic verification only).
    - No live network / node execution.
    - No claim on full liquidation engine or cross-margin position state solver.
    - Node #115 and visor targets excluded.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64 / Windows, Python 3.12+, GNU objdump 2.42+.
The binary is only read offline; nothing is executed.

```sh
python3 tools/artifacts.py verify
python3 tools/margin_table_static.py --out research/work-items/RE-007-margin-table-94
python3 -m unittest tests.test_margin_table_static -v
sha256sum -c research/work-items/RE-007-margin-table-94/MANIFEST.sha256

# Optional human cross-check: disassemble the 3 FDE extents
objdump -d -M intel --start-address=0x3333580 --stop-address=0x333366e artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x3333670 --stop-address=0x33337f9 artifacts/node/94/hl-node
objdump -d -M intel --start-address=0x3333800 --stop-address=0x3333915 artifacts/node/94/hl-node
```

### Repository verification status & environment limits
- `tools/artifacts.py verify`: All 8 artifact SHA-256 digests verified OK (including `artifacts/node/94/hl-node: 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
- `tools/verify_imports.py`: Verified 37 imported files and all pinned source repositories.
- `make verify` / `make test` / `make catalogue-check`: Full repo-level make harness was not run directly in this environment due to missing native POSIX make/gpg toolchains on Windows. All unit tests for this packet (`tests/test_margin_table_static.py`) pass 12/12 cleanly.
- Differential/runtime execution: Intentionally excluded. Offline static observation only; no binary execution or runtime equivalence claim.

## Evidence

Coordinates are ELF virtual addresses (VA). `.rodata` VA equals file offset; `.text` VA = file offset + 0x1000;
`.data.rel.ro` and `.got` VA = file offset + 0x2000.

### 1. Function Extents and Disassembly Analysis

| Routine | ELF VA Range | File Offset | Size | SHA-256 |
| --- | --- | --- | ---: | --- |
| `max_leverage_for_position` | `0x3333580..0x333366e` | `0x3332580..0x333266e` | 238 B | `70a264b0719c28fec54a5c7aab0d8d50c133795abf14ef1ec43a17938616bb1e` |
| `margin_after_tier_offset_div_6x_leverage` | `0x3333670..0x33337f9` | `0x3332670..0x33327f9` | 393 B | `3c931bafcdd34ed228728e61b2c7fc1e1a21b66ffe554d8a4c87bde083ba82f9` |
| `ntl_div_2x_leverage_minus_prior_contribution` | `0x3333800..0x3333915` | `0x3332800..0x3332915` | 277 B | `2774ef152d00b90e6d846604c65ada3efc7d58de4865338d84c49235e33e79f8` |

#### A. Position Leverage Calculation (`0x3333580..0x333366e`)
- Checks tier presence: `mov rsi, [rdi+0x18]; test rsi, rsi; je 0x3333665`.
- Empty fallback: At `0x3333665`, sets `mov al, 0x32` (50 decimal) and returns (`MAX_MARGIN_LEVERAGE = 50`).
- Position absolute size: `mov rcx, rdx; neg rcx; cmovs rcx, rdx` computes `abs(signed_sz)`.
- Position notional: `mul rcx` multiplies `px` by `abs_sz` with saturation checks.
- Tier lookup: B-tree / tier scan invokes `call 0x2fe1670` to locate applicable lower-bound tier.
- Returns `max_leverage` (`movzx eax, byte ptr [...]`).

#### B. Tier Offset Margin Formula (`0x3333670..0x33337f9`)
- Disassembly proves formula: `(2 * notional - 4 * leverage * prior_contribution) / (6 * leverage)`:
  - `add rbx, rbx`: scales notional by 2 (`2 * notional`).
  - `lea eax, [rcx*4]`: scales leverage by 4 (`4 * leverage`).
  - `mul [r14-0x10]`: multiplies by `prior_contribution`.
  - `sub rbx, rax` with `jae`: saturates at 0 on underflow (`xor ebx, ebx`).
  - `add ecx, ecx; lea rcx, [rcx+rcx*2]`: computes divisor `2 * leverage + 4 * leverage = 6 * leverage`.
  - `div rcx`: divides saturated numerator by `6 * leverage`.
- Underflow / boundary guard invokes panic record `0x56e9b40` at `0x33337a9`.

#### C. Mode-2 Tier Contribution Formula (`0x3333800..0x3333915`)
- Disassembly proves formula: `notional / (2 * leverage) - prior_contribution` (saturating at zero):
  - `movzx esi, byte ptr [rax+rdx*1-0x8]`: loads tier's `max_leverage`.
  - `add esi, esi`: computes divisor `2 * max_leverage`.
  - `div rsi`: computes `notional / (2 * max_leverage)`.
  - `sub rax, [rcx-0x10]`: subtracts `prior_contribution`.
  - `jae 0x33338e2` with underflow fallback `xor eax, eax`: ensures saturating subtraction.

### 2. Relocations and Source Locations

- Dynamic relocations in `.rela.dyn` (`info = 0x8` / `R_X86_64_RELATIVE`):
  - `0x5775998`: addend `0x3333580` (`max_leverage_for_position`)
  - `0x57759a0`: addend `0x3333670` (`margin_after_tier_offset_div_6x_leverage`)
  - `0x57746e8`: addend `0x3333800` (`ntl_div_2x_leverage_minus_prior_contribution`)
- Static panic location records in `.data.rel.ro`:
  - `0x56e9b40`: line 107, column 105 (`margin_table.rs`)
  - `0x56e9b58`: line 101, column 57 (`margin_table.rs`)
- Source file literal:
  - `.rodata` VA `0x1fc39b`: `/home/ubuntu/hl/code_Mainnet/l1/src/clearinghouse/margin_table.rs` (65 bytes, null-terminated).

## Implementation and comparison

Not yet implemented in reconstructed Rust.
An independent clean-room Rust implementation of `MarginTable` must:
1. Guarantee `max_leverage_for_position` returns fallback `50` when tiers are empty.
2. Mirror saturating behavior on `abs_sz * px` and saturating subtraction before division.
3. Match integer division rules (truncating toward zero) for `6 * leverage` and `2 * leverage`.
4. Be independently authored under MIT license without copying from unlicensed reference repositories.
5. No runtime or binary equivalence claim is made.

## Results and limitations

- Metrics (explicit denominators):
  - FDE function extents mapped and verified: 3/3 (100%).
  - Panic location records mapped to source coordinates: 2/2 (100%).
  - Relocation slots verified: 3/3 (100%).
  - Fallback leverage constant verified: 50x (`0x32`).
- Limitations & Inferences:
  - Higher-level risk engine caller context (e.g. cross-margin solvers, liquidation engines) is excluded.
  - Node #115 and visor differences are not evaluated.
- No progress gate is requested.

Next question: How are `MarginTable` instances serialized and updated via governance / exchange actions in node #94?
