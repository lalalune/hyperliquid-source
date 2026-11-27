# RE-008-node115-block-rules-and-tc-verify: consensus block validation rules (`0x59d6b80`, `signed.rs:194`) and timeout certificate verification (`0x5960390`)

- Component ID: `consensus` (`RE-008`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `main` base `e0978f807`; no reference source copied
- Claim status: **observation** for all FDE extents, Capstone 5.0.7 instruction rows, relocation slots, and `.rodata` literal in `records.json`; **inference** where protocol names (`Block::verify_rules`, `TimeoutCertificate::verify`, `extra_qc`) are assigned; **unresolved** items listed under Results and limitations.
- Scope included and excluded:
  - Included (3 FDE-bounded functions, 2,839 bytes total):
    1. `0x59d6b80..0x59d70ab` (1,323 B, `node/src/consensus/signed.rs:194`, slot `0x64e64c0`) — block validation rules called after signer check by `0x2786870`.
    2. `0x5960390..0x59608a8` (1,304 B) — timeout certificate verifier called by `0x59d6b80` on timeout-recovery blocks.
    3. `0x564b510..0x564b5e4` (212 B) — TC parallel signature-verification dispatch leaf.
  - Excluded: parallel rayon scheduler internals (`0x5aac2c0` / `0x5b3dde0`, covered as reduction boundary in `RE-008-tc-parallel-abort-115`), curve recovery internals, native byte comparison, live execution, and whole-ELF equivalence.

## Reproduce

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-008-node115-block-rules-and-tc-verify/verify.py
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tests.test_node115_block_rules_and_tc_verify
(cd research/work-items/RE-008-node115-block-rules-and-tc-verify && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/consensus-staking \
  cargo test --offline --locked --manifest-path src/node115-consensus/Cargo.toml
```

## Evidence

### 1. Block validation rules (`0x59d6b80..0x59d70ab`, `node/src/consensus/signed.rs:194`)

1. **Block round (`0x59d6b9a..0x59d6bd6`)**: reads `[block+0x18]`; if equal to `0x8000000000000001` (`tc == None`), `parent_round = [block+0x50]` (`qc.round`), else `parent_round = [block+0xa0]` (`tc.round`). Computes `block_round = parent_round.saturating_add(1)`.
2. **Proposer verification (`0x59d6bd7..0x59d6eb2`)**: selects `stake_round` from `[block+0x18]` / `[block+0xa8]` (`None` -> `+0x60`; `Some, None` -> `+0x58`; `Some, Some` -> `+0xe8`), calls proposer selection through slot `0x64e86f0` (`0x595cb30`). Non-`0x2e` error is copied verbatim (`0x48` bytes). Compares expected 20-byte proposer with `block+0x11c..+0x130` (SIMD `pcmpeqb` + `pmovmskb == 0xffff`). On mismatch, computes block digest (`0x57e8d40`), logs `"Unexpected proposer for block"` (`0x9385ff`), and returns tag **`0x0d`** with `(block.proposer, expected_proposer)`.
3. **Transaction-hash cap (`0x59d6f04..0x59d6f17`)**: reads `len = [block+0x10]`; if `len > 100` (`0x64`), returns tag **`0x29`** with `len` at `+8`.
4. **Transaction-hash uniqueness (`0x59d6f50..0x59d6fa5`)**: inserts each 32-byte hash via `0x51d28d0`; on first duplicate (`al != 0`), returns tag **`0x2a`** with the 32-byte duplicate hash at `+1..+0x21`.
5. **Certificate verification (`0x59d6fa5..0x59d7089`)**:
   - If `tc == None`: delegates directly to `0x595fd20` (`decide_nested`) on primary QC (`block+0x20`).
   - If `tc == Some(tc)`:
     - If optional `extra_qc` (`block+0xa8`) is `Some`: reads `extra_qc_round = [block+0xd8]` and requires **`tc.high_qc.round ([block+0x48]) < extra_qc_round < tc.round ([block+0xa0])`** (`jbe` / `jae` -> tag **`0x0c`** with `extra_qc_round` at `+8`).
     - Calls `0x5960390` (`verify_tc`) on `tc`; any non-`0x2e` tag is copied verbatim.
     - If `extra_qc` is `Some`: calls `0x595fd20` (`decide_nested`) on `extra_qc`; any non-`0x2e` tag is copied verbatim.
     - Returns tag **`0x2e`** (`Ok`).

### 2. TimeoutCertificate verification (`0x5960390..0x59608a8`)

1. Calls stake-set provider through slot `0x64e64b0` (`0x595e5c0`) for `[tc+0x40]` (`high_qc.f40`); non-`0x2e` error returned verbatim.
2. Calls signer collector `0x4dffc40(stake_set, &tc.signatures)` verifying every signer is in the stake map; non-`0x2e` error (e.g. `0x2c`) returned verbatim.
3. Scans `tc.signatures` (`0x68`-byte ring elements or B-tree): empty signatures jump to **`0x08`** (`0x59605a0 -> 0x596079c`); otherwise computes `max_signed_high_qc_round` (`r13`).
4. Round consistency (`0x59606ef..0x5960705`): requires **`tc.high_qc.f30 == max_signed_high_qc_round`** AND **`max_signed_high_qc_round < tc.round`** (`jne` / `jae` -> tag **`0x0b`** at `0x59607b1`).
5. Calls consensus quorum through slot `0x64e8780` (`0x595bc40`); `false` -> tag **`0x08`** (`0x596079c`).
6. Calls `0x595fd20` (`decide_nested`) on `tc.high_qc`; non-`0x2e` error copied verbatim (`0x5960805`).
7. Calls `0x564b510` to verify each signer's variant-2 timeout signature (`(ctx.pair, tc.round, entry.high_qc_round, signer)`), returning tag **`0x2e`** iff all verify.

## Implementation and comparison

Independently authored Rust modules [`tc_verify.rs`](../../../src/node115-consensus/src/tc_verify.rs) and [`block_rules.rs`](../../../src/node115-consensus/src/block_rules.rs) are integrated into `src/node115-consensus`, wiring directly with `admission`, `nested_certificate`, and `round_progression`. All 6 in-memory corruption controls in `verify.py` are caught.

## Results and limitations

- Verified: 3 FDEs (2,839 bytes), 11 anchored instruction windows, 16 relocation/literal/call facts, 6/6 negative controls caught.
- No component acceptance gate is requested by this packet alone.
- Next question: decode `0x2e13ea0` (`try_propose`) and `0x2705af0`/`0x2e08b90` to connect block & timeout reception directly into `ConsensusState`.
