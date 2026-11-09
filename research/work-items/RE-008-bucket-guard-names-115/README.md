# RE-008: node #115 `bucket_guard/{}` observers: names, keyed map and what they time

- Component ID: abci. Question: the observer catalogue (open PR #5850) found 50 record calls through four getters that build observers named `bucket_guard/{}`, all with the Location `base/src/bucket_guard.rs:118:21`. What fills the `{}`, how do the getters find an existing observer, and what does each guard time?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5045 (observer, first stage) and #5850 (catalogue). It does not depend on their files.
- Claim status: instruction bytes, call censuses, relocations, GOT symbols, string bytes and constant bytes are observations. "Getter", "wrapper", "guard", "name", "pair", "B-tree" and "elapsed seconds" are inferred labels from the calling pattern and layout. The binary was not executed.
- Scope included: the four getters (`0x26d4660`, `0x3704070`, `0x4770930`, `0x51eaff0`), their 50 direct calls, the name and f64 pair that reach each call, the global each call loads, and the clock reads in each enclosing function. Scope excluded: what the pair values mean inside the observer, the condition that sets a guard's flag byte, the bodies being timed, and the observer entry `0x1547530` itself (earlier stages). No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/bucket_guard_names_115.py --check
python3 -m unittest tests.test_bucket_guard_names_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. `sites.objdump.txt` beside this record was made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read it.

## Evidence 1: the four getters are one `or_insert_with` shape

Each getter takes an entry in `rdi` and a closure in `rsi`:

- Occupied path: `xor eax,eax; cmp rax,[rdi]; jno vacant` (the tag `0x8000000000000000` is the only value that overflows), then `imul rax,[rdi+0x18],0x260; add rax,[rdi+0x8]` and return. The value stride is `0x260` (608) bytes.
- Vacant path: three loads from the closure, `[rsi]` (name), `[rsi+0x8]` and `[rsi+0x10]` (two f64 pointers). The name goes to the format call through slot `0x64df6e8` with the template `0x43bb25` (`bucket_guard/{}`, bytes `0d 'bucket_guard/' c0 00`) and an argument formatter: four thunks (`0x24a7c50`, `0x46dd7f0`, `0x47735c0`, `0x5616320`) with identical bytes `mov rax,rsi; mov rsi,[rdi]; mov rdx,[rdi+8]; mov rdi,rax; jmp [0x64df720]` (slot `R_X86_64_RELATIVE` to `0x167fa70`). Inference: `<&str as Display>::fmt` passing the pointer and length to the formatter's pad routine.
- `*[rsi+0x8]` goes to the constructor `0x1548bb0` in `xmm0` (the constructor stores it at `+0x218` and writes `0` at `+0x0`). After the constructor returns, the getter writes `1` and `*[rsi+0x10]` into the first 16 bytes of the new value (inference: `Some(b)` over the constructor's `None`), copies `0x238` bytes with `memcpy` (GOT `0x64df508`), inserts and returns the new value.

So the `{}` is always a `&str` that the caller puts in the closure. There are no enum tables or numeric arguments.

## Evidence 2: one global map, keyed by the name

All 50 calls sit in functions that load `[rip→0x64e0168]` (`R_X86_64_RELATIVE` to `0x64efc58`, in `.data`) before the getter call. At the first site (`0x2bdf7e9`, `begin_block`), the code takes a lock byte at `+0x0` (`lock cmpxchg`), calls through `0x64df9f0` when the word at `+0x20` is non-zero (inference: one-time init), then searches nodes from `+0x8`: keys at node `+0x1a28` with stride `0x18`, a `u16` length at `+0x1b32`, key bytes compared with `memcmp` (GOT `0x64dfb50`) and the length difference, child edges at `+0x1b38 + 8·i`, and a height counted down to the leaf. A miss builds a vacant entry whose key is an owned copy of the name (capacity = length). Inference: a lazily initialised, mutex-guarded `BTreeMap<String, Observer>`; 11 values × `0x260` = `0x1a20`, which is where the key array begins after one 8-byte field. The `0x260` stride that #5850 read as a table slot is the B-tree value size, so `0x51eaff0` returns an observer from this map, not from a flat table.

## Evidence 3: 22 names over 50 calls

Census of direct calls (`E8 rel32` in `.text`): `0x26d4660` 11, `0x3704070` 8, `0x4770930` 1, `0x51eaff0` 30. A record call through `0x64e1010` follows each one within 48 bytes.

- Static (36 calls): the name struct is on the caller's stack: `&str` pointer from `lea reg,[rip→string]`, length stored by `mov qword [rsp+Y+8],imm32`, and the f64 pair stored 16 bytes after the name (`[rsp+Y+0x10]`) from a 16-byte constant. The closure's first capture is `lea [rsp+Y]`.
- Wrapper (14 calls): the call sits in a function that takes a pointer `p` to the same struct (`name`, `len`, `a`, `b`) as an argument and captures `p`, `p+0x10` and `p+0x18`. The tool pins each of the 24 callers of these 14 functions: the argument `lea` (directly, or through `r14`/`r15`, which no instruction rewrites between the `lea` and the call, checked over objdump), the name, the length and the pair. For `median_risk_free_rate`, `0x3673a10` receives the name in `r9` and its 7th argument slot (`[rsp+0x90]` after its prologue) and passes the copy at `[rsp+0x58]`; its three callers load `lea r9,[rip→0x7bb4e3]` and `mov qword [rsp],0x15`.

| Getter call | Getter | Function | Name source | Name | String, length | Pair (a, b) |
| --- | --- | --- | --- | --- | --- | --- |
| `0x2bdf7e9` | `0x26d4660` | `0x2bdf270` | static | `begin_block` | `0x60e193`, 11 | 0.05, 0.05 |
| `0x2be05ed` | `0x26d4660` | `0x2bdf8f0` | static | `distribute_funding` | `0x60e19e`, 18 | 0.35, 0.05 |
| `0x2be103b` | `0x26d4660` | `0x2bdf8f0` | static | `update_funding_rates` | `0x60e1db`, 20 | 0.01, 0.05 |
| `0x2be17fd` | `0x26d4660` | `0x2bdf8f0` | static | `cancel_aggressive_orders_at_oi_cap` | `0x60e23a`, 34 | 0.01, 0.05 |
| `0x2be1d8d` | `0x26d4660` | `0x2bdf8f0` | static | `prune_book_empty_user_states` | `0x60e21e`, 28 | 0.05, 0.05 |
| `0x2be6b6b` | `0x26d4660` | `0x2bdf8f0` | static | `refresh_main_perp_dex_stale_oracle` | `0x60e25c`, 34 | 0.01, 0.05 |
| `0x2be797d` | `0x26d4660` | `0x2bdf8f0` | static | `refresh_hip3_stale_mark_pxs` | `0x60e203`, 27 | 0.01, 0.05 |
| `0x2be82fb` | `0x26d4660` | `0x2bdf8f0` | static | `apply_bole_liquidations` | `0x60e1b0`, 23 | 0.01, 0.05 |
| `0x2c72412` | `0x26d4660` | `0x2c71eb0` | static | `build_small_evm_block_and_apply_l1_effects` | `0x60ea04`, 42 | 0.03, 0.07 |
| `0x2c728f5` | `0x26d4660` | `0x2c71eb0` | static | `build_big_evm_block_and_apply_l1_effects` | `0x60ea2e`, 40 | 0.05, 0.05 |
| `0x2c7e411` | `0x26d4660` | `0x2c7e0b0` (wrapper) | caller `0x2d1d80c` (rdi) | `hyperliquidity_ensure_orders` | `0x616aa1`, 28 | 0.03, 0.05 |
| `0x422a53e` | `0x3704070` | `0x4229fe0` (wrapper) | caller `0x2be608b` (rdi) | `reset_recent_ois` | `0x453d80`, 16 | 0.01, 0.05 |
| `0x422a53e` | `0x3704070` | `0x4229fe0` (wrapper) | caller `0x54b09bb` (rdi) | `reset_recent_ois` | `0x453d80`, 16 | 0.01, 0.05 |
| `0x422a53e` | `0x3704070` | `0x4229fe0` (wrapper) | caller `0x54bcffb` (rdi) | `reset_recent_ois` | `0x453d80`, 16 | 0.01, 0.05 |
| `0x422ab27` | `0x3704070` | `0x422a630` (wrapper) | caller `0x3c402fa` (rdi) | `decay_staking` | `0x7bbee3`, 13 | 0.01, 0.05 |
| `0x422c0c4` | `0x3704070` | `0x422abf0` (wrapper) | caller `0x3c3fad4` (rsi) | `c_staking_distribute_staged_rewards` | `0x7bbe6f`, 35 | 0.01, 0.05 |
| `0x422c6be` | `0x3704070` | `0x422c320` (wrapper) | caller `0x3c3f938` (rsi) | `c_staking_stage_reward` | `0x7bbe59`, 22 | 0.01, 0.05 |
| `0x422ce87` | `0x3704070` | `0x422c960` (wrapper) | caller `0x3673b63` (rdi) | `median_risk_free_rate` | via `0x3673a10` (3 callers, `0x7bb4e3`, 21) | 0.01, 0.05 |
| `0x422d361` | `0x3704070` | `0x422cff0` (wrapper) | caller `0x2be1fca` (rdi) | `gas_auction_restart` | `0x7bac52`, 19 | 0.01, 0.05 |
| `0x422d361` | `0x3704070` | `0x422cff0` (wrapper) | caller `0x3d73162` (rdi) | `gas_auction_restart` | `0x7bac52`, 19 | 0.01, 0.05 |
| `0x422d361` | `0x3704070` | `0x422cff0` (wrapper) | caller `0x4230891` (rdi) | `gas_auction_restart` | `0x7bac52`, 19 | 0.01, 0.05 |
| `0x422d361` | `0x3704070` | `0x422cff0` (wrapper) | caller `0x54ac45a` (rdi) | `gas_auction_restart` | `0x7bac52`, 19 | 0.01, 0.05 |
| `0x422d361` | `0x3704070` | `0x422cff0` (wrapper) | caller `0x54b8d8a` (rdi) | `gas_auction_restart` | `0x7bac52`, 19 | 0.01, 0.05 |
| `0x422da1e` | `0x3704070` | `0x422d420` (wrapper) | caller `0x366ee4f` (rdi) | `median_reference_oracle_px` | `0x79d28c`, 26 | 0.01, 0.05 |
| `0x422df01` | `0x3704070` | `0x422dbb0` (wrapper) | caller `0x2be5ce0` (rdi) | `validator_l1_vote_tracker_prune_expired` | `0x79d355`, 39 | 0.01, 0.05 |
| `0x422df01` | `0x3704070` | `0x422dbb0` (wrapper) | caller `0x54b0610` (rdi) | `validator_l1_vote_tracker_prune_expired` | `0x79d355`, 39 | 0.01, 0.05 |
| `0x422df01` | `0x3704070` | `0x422dbb0` (wrapper) | caller `0x54bcc5f` (rdi) | `validator_l1_vote_tracker_prune_expired` | `0x79d355`, 39 | 0.01, 0.05 |
| `0x4780781` | `0x4770930` | `0x4780430` (wrapper) | caller `0x4770e9e` (rdi) | `profiled_rw_lock_increment` | `0x7e1450`, 26 | 0.01, 0.05 |
| `0x5483ddf` | `0x51eaff0` | `0x5483850` | static | `begin_block` | `0x929dad`, 11 | 0.05, 0.05 |
| `0x54844ff` | `0x51eaff0` | `0x5483f50` | static | `begin_block` | `0x929dad`, 11 | 0.05, 0.05 |
| `0x5487122` | `0x51eaff0` | `0x5486720` | static | `build_small_evm_block_and_apply_l1_effects` | `0x92a5cf`, 42 | 0.03, 0.07 |
| `0x54875f5` | `0x51eaff0` | `0x5486720` | static | `build_big_evm_block_and_apply_l1_effects` | `0x92a5f9`, 40 | 0.05, 0.05 |
| `0x548a262` | `0x51eaff0` | `0x54897e0` | static | `build_small_evm_block_and_apply_l1_effects` | `0x92a5cf`, 42 | 0.03, 0.07 |
| `0x548a735` | `0x51eaff0` | `0x54897e0` | static | `build_big_evm_block_and_apply_l1_effects` | `0x92a5f9`, 40 | 0.05, 0.05 |
| `0x54aa9a2` | `0x51eaff0` | `0x54a9c70` | static | `distribute_funding` | `0x929db8`, 18 | 0.35, 0.05 |
| `0x54ab402` | `0x51eaff0` | `0x54a9c70` | static | `update_funding_rates` | `0x929df5`, 20 | 0.01, 0.05 |
| `0x54abc52` | `0x51eaff0` | `0x54a9c70` | static | `cancel_aggressive_orders_at_oi_cap` | `0x929e54`, 34 | 0.01, 0.05 |
| `0x54ac1e2` | `0x51eaff0` | `0x54a9c70` | static | `prune_book_empty_user_states` | `0x929e38`, 28 | 0.05, 0.05 |
| `0x54b1552` | `0x51eaff0` | `0x54a9c70` | static | `refresh_main_perp_dex_stale_oracle` | `0x929e76`, 34 | 0.01, 0.05 |
| `0x54b23c5` | `0x51eaff0` | `0x54a9c70` | static | `refresh_hip3_stale_mark_pxs` | `0x929e1d`, 27 | 0.01, 0.05 |
| `0x54b3792` | `0x51eaff0` | `0x54a9c70` | static | `apply_bole_liquidations` | `0x929dca`, 23 | 0.01, 0.05 |
| `0x54b73c2` | `0x51eaff0` | `0x54b66b0` | static | `distribute_funding` | `0x929db8`, 18 | 0.35, 0.05 |
| `0x54b7e22` | `0x51eaff0` | `0x54b66b0` | static | `update_funding_rates` | `0x929df5`, 20 | 0.01, 0.05 |
| `0x54b85f2` | `0x51eaff0` | `0x54b66b0` | static | `cancel_aggressive_orders_at_oi_cap` | `0x929e54`, 34 | 0.01, 0.05 |
| `0x54b8b42` | `0x51eaff0` | `0x54b66b0` | static | `prune_book_empty_user_states` | `0x929e38`, 28 | 0.05, 0.05 |
| `0x54bdb8f` | `0x51eaff0` | `0x54b66b0` | static | `refresh_main_perp_dex_stale_oracle` | `0x929e76`, 34 | 0.01, 0.05 |
| `0x54bea02` | `0x51eaff0` | `0x54b66b0` | static | `refresh_hip3_stale_mark_pxs` | `0x929e1d`, 27 | 0.01, 0.05 |
| `0x54bfda2` | `0x51eaff0` | `0x54b66b0` | static | `apply_bole_liquidations` | `0x929dca`, 23 | 0.01, 0.05 |
| `0x56176c1` | `0x51eaff0` | `0x5617370` (wrapper) | caller `0x5a5de24` (rdi) | `reset_counters` | `0x938671`, 14 | 0.01, 0.05 |
| `0x56176c1` | `0x51eaff0` | `0x5617370` (wrapper) | caller `0x5a5fffe` (rdi) | `reset_counters` | `0x938671`, 14 | 0.01, 0.05 |
| `0x56176c1` | `0x51eaff0` | `0x5617370` (wrapper) | caller `0x5a62fb8` (rdi) | `reset_counters` | `0x938671`, 14 | 0.01, 0.05 |
| `0x5617ae1` | `0x51eaff0` | `0x5617780` (wrapper) | caller `0x518568c` (rdi) | `hyperliquidity_ensure_orders` | `0x91f289`, 28 | 0.03, 0.05 |
| `0x5617f01` | `0x51eaff0` | `0x5617ba0` (wrapper) | caller `0x518540c` (rdi) | `hyperliquidity_ensure_orders` | `0x91f289`, 28 | 0.03, 0.05 |
| `0x5618311` | `0x51eaff0` | `0x5617fc0` (wrapper) | caller `0x595ee07` (rdi) | `reset_counters` | `0x938671`, 14 | 0.01, 0.05 |
| `0x5647b7e` | `0x51eaff0` | `0x5647720` | static | `slow_abci_engine_read_increment` | `0x92a7f5`, 31 | 0.01, 0.05 |
| `0x56481f8` | `0x51eaff0` | `0x5647da0` | static | `slow_abci_engine_read_increment` | `0x92a7f5`, 31 | 0.01, 0.05 |
| `0x564885e` | `0x51eaff0` | `0x5648400` | static | `slow_abci_engine_read_increment` | `0x92a7f5`, 31 | 0.01, 0.05 |
| `0x5648e88` | `0x51eaff0` | `0x5648a30` | static | `slow_abci_engine_read_increment` | `0x92a7f5`, 31 | 0.01, 0.05 |
| `0x56494be` | `0x51eaff0` | `0x5649060` | static | `slow_abci_engine_read_increment` | `0x92a7f5`, 31 | 0.01, 0.05 |
| `0x564a276` | `0x51eaff0` | `0x5649df0` | static | `slow_abci_engine_read_increment` | `0x92a7f5`, 31 | 0.01, 0.05 |

Names per record call: `slow_abci_engine_read_increment` 6; `apply_bole_liquidations`, `begin_block`, `build_big_evm_block_and_apply_l1_effects`, `build_small_evm_block_and_apply_l1_effects`, `cancel_aggressive_orders_at_oi_cap`, `distribute_funding`, `hyperliquidity_ensure_orders`, `prune_book_empty_user_states`, `refresh_hip3_stale_mark_pxs`, `refresh_main_perp_dex_stale_oracle` and `update_funding_rates` 3 each; `reset_counters` 2; `c_staking_distribute_staged_rewards`, `c_staking_stage_reward`, `decay_staking`, `gas_auction_restart`, `median_reference_oracle_px`, `median_risk_free_rate`, `profiled_rw_lock_increment`, `reset_recent_ois` and `validator_l1_vote_tracker_prune_expired` 1 each. The three-copy names sit in three caller functions each, one using `0x26d4660` and two using `0x51eaff0` (inference: monomorphized copies of one caller). Pairs: (0.01, 0.05) 42, (0.05, 0.05) 9, (0.35, 0.05) 3 (`distribute_funding`), (0.03, 0.07) 3 (`build_small_evm_block_and_apply_l1_effects`), (0.03, 0.05) 3 (`hyperliquidity_ensure_orders`).

## Evidence 4: each guard times its body with CLOCK_MONOTONIC

Every enclosing function (static site or wrapper) has at least two `mov edi,1; call 0x5c842e0`. `0x5c842e0` calls `clock_gettime` through GOT `0x64e1248` (`R_X86_64_GLOB_DAT`, `.dynsym` name `clock_gettime`); `1` is `CLOCK_MONOTONIC`. At the first site (excerpt), the reads bracket the body call `0x2bdf8f0`, the difference is converted to seconds (`secs + nanos / 1e9`, constant `0x458d50` = 1e9), the value becomes `0.0` when the subtraction fails or gives `+inf` (constant `0x459010`), and that value is the record call's `xmm0`. The wrapper `0x5617370` (excerpt) has the same sequence and first tests the guard's flag byte at `p+0x20`; the other wrappers were checked only for the two clock reads. Inference: each `bucket_guard` observer records the wall time of the named step, in seconds.

## Limits

Not mapped: what `a` (constructor `xmm0`, stored at observer `+0x218`) and `b` (the `Some(b)` at `+0x0`) do in the observer; the condition that sets the flag byte (at `begin_block` it is a comparison at `0x2bdf448`); the bodies being timed; the two BTreeMap fields between the values and keys beyond the layout above; and whether all four getters are one source function (their identical shape and shared Location suggest it). The step names are strings in the binary; that they name the timed function is an inference. The four getters and 14 wrappers are found by direct calls only; an indirect caller would not be counted.
