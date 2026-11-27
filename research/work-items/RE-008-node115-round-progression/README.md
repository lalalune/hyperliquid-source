# RE-008-node115-round-progression: consensus timeout quorum, 1/3 amplification, TC high-QC selection, jailed-validator provider, and round advancement

- Component ID: `consensus` (`RE-008`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `main` base `179eef45a4067293bb8ed969798883af5931c608`; no reference source copied
- Claim status: **observation** for all FDE extents, instruction rows, relocation slots, and literals verified in `records.json`; **inference** where protocol names (e.g., `TimeoutCertificate`, `advance_round`, `f+1` timeout amplification) are assigned; **unresolved** items listed under Results and limitations.
- Scope included and excluded:
  - Included (5 FDE-bounded functions, 6,297 bytes total):
    1. `0x595c3a0..0x595c5f3` (595 B, `node/src/consensus/validator_set.rs:164`) — jailed-validator history lookup by round.
    2. `0x5960010..0x5960381` (881 B) — timeout-certificate builder selecting the highest `high_qc.round`.
    3. `0x2e112f0..0x2e11afb` (2,059 B, `node/src/consensus/state.rs:1193` + `validator_stakes.rs:26,30`) — timeout quorum check, 1/3 stake timeout amplification, TC construction, and round advance dispatch.
    4. `0x2e154e0..0x2e157b2` (722 B) — local timeout signing/broadcast flag update and outbound queue push (tag `2`, conditional tag `3`).
    5. `0x2e19920..0x2e1a118` (2,040 B, `node/src/consensus/timer.rs:23`) — round advancement, telemetry metric classification (`6`/`7`/`8`), timeout state reset, and primary + conditional leader timer reset.
  - Excluded: full body of `0x2e13ea0` (proposal builder), `0x2786260` (timeout signer), `0x59615d0` / `0x4dbf950` (TC signature map builder), network transport, live execution, and whole-ELF equivalence.

## Reproduce

Run from the repository root with Python 3, Capstone 5.0.7, and Rust 1.95.0 (target ELF is read-only and never executed):

```sh
python3 research/work-items/RE-008-node115-round-progression/verify.py
python3 -m unittest tests.test_node115_round_progression
(cd research/work-items/RE-008-node115-round-progression && sha256sum -c MANIFEST.sha256)
CARGO_BUILD_JOBS=4 RUST_TEST_THREADS=4 CARGO_TARGET_DIR=work/target/consensus-staking \
  cargo test --offline --manifest-path src/node115-consensus/Cargo.toml
```

## Evidence

Coordinates are ELF virtual addresses in `.text`, `.rodata`, and `.rela.dyn` (type 8 = `R_X86_64_RELATIVE`). Every function start and end equals its `.eh_frame` FDE, and every selected instruction window is verified by Capstone 5.0.7 decoding from its enclosing FDE start.

### 1. Jailed-validator history lookup (`0x595c3a0..0x595c5f3`, `validator_set.rs:164`)

- Reads `base_warn = [rsi+0x20]`, `exec_round = [rsi+0x60]`, `base_jailed = [rsi+0x48]`, history structure at `rsi+0x28`.
- Warning threshold (`0x595c3d0..0x595c42b`):
  - `limit_a = base_warn.saturating_add(2000)` (`0x7d0`)
  - `limit_b = exec_round.saturating_add(200).saturating_add(1)` (`0xc8`, then `inc`, saturating on overflow)
  - `limit = max(limit_a, limit_b)`
  - If `round >= limit`: atomically increments `[rsi+0x68]` (`lock inc`) and logs via slot `0x64e0b18` (`0x150b310`) with literal `"jailed validators"` (`0x9383de`, 17 bytes) and format string at `0x43d23c`, then continues without rejecting.
- Query round (`0x595c53c..0x595c57f`):
  - `query_round = if round < base_jailed.saturating_add(2000) { base_jailed } else { max(base_jailed, round.wrapping_sub(200)) }`
- Looks up greatest entry `<= query_round` via `0x4dce7b0` (and `0x51f5470` for the B-tree arm, or `0x20`-byte slice tail for the flat arm).
- Output tags (`0x595c5ca..0x595c5e5`): `0x2e` with pointer at `+8` on hit; `0x28` with requested `round` at `+8` on miss.

### 2. TimeoutCertificate construction (`0x5960010..0x5960381`)

- Signature: `(out, round: u64, timeouts: Vec<TimeoutMsg>)` where each `TimeoutMsg` is `0xe0` bytes.
- Empty check (`0x5960031..0x596006a`): if `timeouts.len() == 0`, writes `0x8000000000000001` (`None` niche) to `[out]`, drops the vector, and returns.
- Selection loop (`0x59600d0..0x596012e`): scans `TimeoutMsg` elements comparing `u64` at `+0x30` (`high_qc.round`) via `cmp cur, cand; cmova cand_ptr, cur_ptr; cmovbe cur, cand`. Because `cmovbe` triggers on equality (`cur <= cand`), ties select the **last** element achieving the maximum `high_qc.round`.
- Clones the selected `0x68`-byte `high_qc`, collects signatures via `0x59615d0` and `0x4dbf950`, copies `0x88` bytes to `out`, and writes `round` at `[out+0x88]` (`0x5960308`).

### 3. Timeout quorum, 1/3 amplification, and round-advance dispatch (`0x2e112f0..0x2e11afb`, `state.rs:1193`)

- Scans `state+0x818` (`0xf8`-byte `(Address, TimeoutMsg)` ring or B-tree) for the last-wins maximum `msg+0x30` entry (`best`). If empty, writes tag `0x2e` and returns.
- Calls stake-set provider through slot `0x64e64b0` (`0x595e5c0`) for `[best+0x40]`; any tag other than `0x2e` is copied verbatim (`0x48` bytes) to `out` and returned.
- Collects signer keys (`0x22bce50`), computes saturating `signed_stake = 0x4e44c00(...)` and `total_stake = 0x4e406f0(...)`, and calls consensus quorum through slot `0x64e8780` (`0x595bc40`).
- **1/3 stake timeout amplification (`0x2e118c5..0x2e118f2`, `0x2e11ac8`)**:
  - Guard: `BYTE PTR [state+0x8d0] != 1` (not yet timed out this round).
  - Arithmetic: `mul 3` on `signed_stake`; on 64-bit overflow (`jo 0x2e11ac8`), saturates product to `u64::MAX`, then compares `product > total_stake` (`ja`). Note the boundary: when `total_stake == u64::MAX`, even an overflowing `3 * signed_stake` produces `u64::MAX > u64::MAX == false` and does NOT amplify.
  - When triggered, calls `0x2e154e0(state)`.
- **2/3 quorum TC handoff (`0x2e118f2..0x2e11a2c`)**:
  - If quorum (`0x595bc40`) returned true: resets `state+0x818` to empty `{0, 8, 0, 0}`, drains entries via `0x2351d60`, builds TC via slot `0x64e8788` (`0x5960010`) with `cur_round = [state+0xae0]`.
  - If `Some(tc)` (first word `!= 0x8000000000000001`), calls `0x2e19920(state, tc.round, Some(tc))`.
  - If `0x2e19920` returns true, calls `0x2e13ea0(state)`.
  - Writes tag `0x2e` and returns.

### 4. Local timeout broadcast (`0x2e154e0..0x2e157b2`)

- Clones `high_qc` from `state+0x720..+0x788`, reads `cur_round = [state+0xae0]` and validator address `[state+0xbc0..+0xbd4]`, signs timeout via `0x2786260`.
- Sets `BYTE PTR [state+0x8d0] = 1` (`0x2e15691`).
- Pushes `0x178`-byte outbound record with tag `0x8000000000000002` to queue at `state+0x3c0` (growing via slot `0x64e86d8` = `0x59631f0`).
- If `[state+0x838] != 0x8000000000000001` (`last_tc` is `Some`), clones `last_tc` via `0x2e30150` and pushes a second `0x178`-byte outbound record with tag `0x8000000000000003`.

### 5. Round advancement (`0x2e19920..0x2e1a118`, `timer.rs:23`)

- Reads `cur_round = [state+0xae0]`.
- Stale check (`0x2e19948..0x2e1998e`): if `cert_round < cur_round`, drops `opt_tc` (if `Some`) and returns `false` (`setae al` at `0x2e19fe0`).
- Advance (`0x2e19950..0x2e19961`): `new_round = cert_round.saturating_add(1)`; stored at `[state+0xae0]`.
- Metric code (`0x2e19b67..0x2e19b8c`):
  - If `cert_round == cur_round` and `opt_tc.is_none()`: `6` (`(1 ^ 7)`)
  - If `cert_round == cur_round` and `opt_tc.is_some()`: `7` (`(0 ^ 7)`)
  - If `cert_round > cur_round`: `8`
- If `opt_tc.is_some()`: queries proposers for `cur_round` and `cur_round.saturating_add(1)` via slot `0x64e86f0` (`0x595cb30`), classifies transition kind: `0` (`cert_round == cur_round && last_voted_round != cur_round`), `1` (`cert_round == cur_round && last_voted_round == cur_round`), `2` (`cert_round > cur_round`).
- State reset (`0x2e19dad..0x2e19df7`): resets `state+0x818` to `{0, 8, 0, 0}`, copies `0x90`-byte `opt_tc` into `state+0x838`, zeroes `u64` at `state+0x8c8` and `u16` flags at `state+0x8d0`.
- Timers (`0x2e19dfa..0x2e19f4d`): resets primary timer (`state+0xa88/+0xa90/+0xa98`) and sets enabled byte `[state+0xaa0] = 1`; queries proposer for `new_round` via `0x64e86f0` (`0x595cb30`) and, if `Ok(proposer)` matches `state+0xbc0..+0xbd4` (20-byte SIMD compare), resets secondary/leader timer (`state+0xaa8/+0xab0/+0xab8`) and sets enabled byte `[state+0xac0] = 1`.
- Returns `true`.

### Inferences (kept separate from observations)

- Naming `state+0x818` as `timeouts`, `state+0x838` as `last_tc`, `state+0x8d0` as `timed_out_this_round`, `state+0xae0` as `round`, `state+0xae8` as `last_voted_round`, and `0x2e13ea0` as `try_propose` is inferred from field usage, HotStuff state transitions, and adjacent `state.rs` / `validator_set.rs` / `timer.rs` source-location anchors.

## Implementation and comparison

Independently authored Rust reconstruction lives in [`src/node115-consensus`](../../../src/node115-consensus/Cargo.toml), joining ten existing #115 consensus micro-crates with new `round_progression`, `admission`, and `timeout_flow` modules. No native byte comparison or whole-ELF claim is made here. Six in-memory corruption controls in `verify.py` (corrupted literal, modified amplification multiplier, inverted `setae`, modified niche increment, shifted relocation slot, zeroed call target) are all detected.

## Results and limitations

- Verified: 5 FDEs (6,297 bytes, 1,308 Capstone 5.0.7 instructions), 15 anchored instruction windows, 23 relocation/literal/call facts, 6/6 negative controls caught.
- No component acceptance gate is requested by this packet alone (`consensus` still requires full coverage of `server.rs`, `rpc.rs`, `mempool.rs`, `network.rs`, and `0x2e13ea0` proposal construction).
- Next question: decode `0x2e13ea0` (`try_propose`) and `0x2705af0` / `0x2e098e0` block/vote ingestion arms so the full HotStuff state machine loop closes end to end.
