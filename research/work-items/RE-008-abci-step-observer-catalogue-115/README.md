# RE-008: node #115 shared value observer `0x1547530` (fourth stage): catalogue of observer instances

- Component ID: abci. Question: which observers does node #115 build with the constructor `0x1548bb0`, under which names, and which call sites record into them through `0x1547530`? The earlier stages (open PRs #5045, #5839, #5841) mapped the observer entry, its window, the constructor and the ×50 flag, but named only five instances.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5045 (first stage), #5839 (second stage) and #5841 (third stage). It does not depend on their files.
- Claim status: instruction bytes, call censuses, relocations, string bytes, template bytes and Location records are observations. "Name", "template", "getter" and "Location" are inferred labels from the calling pattern and layout. The constructor's `rdx`/`rcx` are read as the name pointer and length (the pattern #5841 used). The record call's `rdx` is read as a `core::panic::Location` (`&str` file, `u32` line, `u32` column), decoded through its `R_X86_64_RELATIVE` file pointer. The binary was not executed.
- Scope included: every `FF15` call through the constructor slot `0x64e1020` (35) and the record slot `0x64e1010` (68). For each constructor call: the name source and the `esi` byte. For each record call: the `rdi` setup, the getter when `rdi` is a direct call's return value, and the Location. Scope excluded: the window-record consumer `0x1546570` (separate work), the values formatted into `{}` slots, the constructor's `xmm0` argument, the callers of the two name-passed-in sites, and which observer each register-sourced record call uses. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_step_observer_catalogue_115.py --check
python3 -m unittest tests.test_abci_step_observer_catalogue_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. `constructor-sites.objdump.txt` and `record-sites.objdump.txt` beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: 35 constructor calls, 17 names

The census of `FF15` calls through `0x64e1020` (`R_X86_64_RELATIVE` to `0x1548bb0`) in `.text` is exactly 35, as #5839 counted. Each site passes its name one of three ways:

- static (9): `lea rdx, [rip+...]` to a string, and `mov ecx, imm32` with its exact byte length;
- formatted (24): `lea rsi, [rip+...]` to a template, a call through the format slot `0x64df6e8` (`R_X86_64_RELATIVE` to `0x141e3a0`), then the constructor. Templates decode with the rule #5841 used: a length byte and that many literal bytes; `0xc0` for an argument, followed by the next literal's length; `0x00` at the end;
- passed in (2): the name pointer is loaded from memory.

| Constructor call | Function (FDE) | Kind | Name | Source | `esi` |
| --- | --- | --- | --- | --- | --- |
| `0x15d86de` | `0x15d86b0..0x15d8722` | static | `tokio_spawn_forever_scheduled` | `0x469bb4`, length 29 | 1 |
| `0x15ed4ca` | `0x15ed290..0x15ed954` | passed | `(from caller)` | load `488b5308` at `0x15ed4b0` | 1 |
| `0x16eebfc` | `0x16eeaa0..0x16eee4d` | formatted | `profiled_mutex/{}/acquire_all` | template `0x438af2`, format call `0x16eebc4` | 0 |
| `0x16eeeaf` | `0x16eee50..0x16eef3f` | formatted | `profiled_mutex/{}/compute/{}` | template `0x44c834`, format call `0x16eee8b` | 0 |
| `0x2502548` | `0x2502450..0x2502740` | formatted | `profiled_mutex/{}/acquire_all` | template `0x438af2`, format call `0x2502517` | 0 |
| `0x25028f6` | `0x2502780..0x2502b4c` | formatted | `profiled_mutex/{}/acquire_all` | template `0x438af2`, format call `0x25028bc` | 0 |
| `0x2502ce0` | `0x2502b50..0x2502f3a` | formatted | `profiled_mutex/{}/acquire_all` | template `0x438af2`, format call `0x2502ca8` | 0 |
| `0x2503157` | `0x2502f40..0x25033fb` | formatted | `profiled_mutex/{}/acquire_all` | template `0x438af2`, format call `0x2503120` | 0 |
| `0x250345f` | `0x2503400..0x25034ef` | formatted | `profiled_mutex/{}/compute/{}` | template `0x44c834`, format call `0x250343b` | 0 |
| `0x26d4700` | `0x26d4660..0x26d47fb` | formatted | `bucket_guard/{}` | template `0x43bb25`, format call `0x26d46e1` | 0 |
| `0x2aec668` | `0x2aeaef0..0x2af0654` | static | `run_node_compute_resps_hash` | `0x605b39`, length 27 | 0 |
| `0x2af5722` | `0x2af45f0..0x2af652a` | static | `execution_sender` | `0x455ee0`, length 16 | 0 |
| `0x2cb7c88` | `0x2cb6500..0x2cbbbdf` | static | `run_node_compute_resps_hash` | `0x60ef93`, length 27 | 0 |
| `0x2cc243e` | `0x2cc1120..0x2cc971b` | static | `execution_sender` | `0x455ee0`, length 16 | 0 |
| `0x2f1954d` | `0x2f19520..0x2f1962b` | static | `handle_request_rate_limiter` | `0x644408`, length 27 | 0 |
| `0x3704110` | `0x3704070..0x370420b` | formatted | `bucket_guard/{}` | template `0x43bb25`, format call `0x37040f1` | 0 |
| `0x47709d6` | `0x4770930..0x4770c21` | formatted | `bucket_guard/{}` | template `0x43bb25`, format call `0x47709b6` | 0 |
| `0x47712ee` | `0x47710e0..0x477165a` | formatted | `profiled_mutex/{}/acquire_all` | template `0x438af2`, format call `0x47712b4` | 0 |
| `0x47716bf` | `0x4771660..0x477174f` | formatted | `profiled_mutex/{}/compute/{}` | template `0x44c834`, format call `0x477169b` | 0 |
| `0x477229a` | `0x47721f0..0x4772528` | formatted | `profiled_rw_lock/{}/acquire_{}_all` | template `0x434d59`, format call `0x4772267` | 0 |
| `0x4772914` | `0x4772530..0x47729e3` | formatted | `profiled_rw_lock/{}/{}` | template `0x432e2d`, format call `0x47728e8` | 0 |
| `0x47857a6` | `0x47855c0..0x4785a0a` | formatted | `tcp_lz4/{}_{}` | template `0x44f828`, format call `0x4785769` | 1 |
| `0x4da5e29` | `0x4da5d60..0x4da5f8a` | formatted | `{}/{}/{}` | template `0x440e47`, format call `0x4da5e01` | 0 |
| `0x4da6549` | `0x4da64e0..0x4da66d9` | passed | `(from caller)` | load `488b5008` at `0x4da652c` | 1 |
| `0x4da8017` | `0x4da7e20..0x4da81a5` | formatted | `{}/{}/{}` | template `0x440e47`, format call `0x4da7ff1` | 0 |
| `0x4dfe5ac` | `0x4dfe550..0x4dfe6c6` | static | `execution_sender` | `0x455ee0`, length 16 | 0 |
| `0x51c9d22` | `0x51c9cb0..0x51c9fc5` | formatted | `{}_block_duration` | template `0x44cbea`, format call `0x51c9cfb` | 0 |
| `0x51c9d82` | `0x51c9cb0..0x51c9fc5` | formatted | `{}_backlog_from_node` | template `0x430c15`, format call `0x51c9d4c` | 1 |
| `0x51c9dd3` | `0x51c9cb0..0x51c9fc5` | formatted | `{}_begin_block_to_commit` | template `0x440603`, format call `0x51c9dac` | 0 |
| `0x51eb090` | `0x51eaff0..0x51eb18b` | formatted | `bucket_guard/{}` | template `0x43bb25`, format call `0x51eb071` | 0 |
| `0x594505b` | `0x5945030..0x594509f` | static | `proposer` | `0x459ad0`, length 8 | 0 |
| `0x5a6c496` | `0x5a6bfb0..0x5a6c8ec` | static | `vote_abci_digest` | `0x456200`, length 16 | 0 |
| `0x5ab1e4c` | `0x5ab1ce0..0x5ab20c6` | formatted | `profiled_mutex/{}/acquire_all` | template `0x438af2`, format call `0x5ab1e14` | 0 |
| `0x5ab2277` | `0x5ab20d0..0x5ab24f6` | formatted | `profiled_mutex/{}/acquire_all` | template `0x438af2`, format call `0x5ab223f` | 0 |
| `0x5ab255f` | `0x5ab2500..0x5ab25ef` | formatted | `profiled_mutex/{}/compute/{}` | template `0x44c834`, format call `0x5ab253b` | 0 |

Grouped: `profiled_mutex/{}/acquire_all` 8, `profiled_mutex/{}/compute/{}` 4 (the ×50 sites of #5841), `bucket_guard/{}` 4, `execution_sender` 3, `run_node_compute_resps_hash` 2, `{}/{}/{}` 2, name passed in 2, and one each of `profiled_rw_lock/{}/acquire_{}_all`, `profiled_rw_lock/{}/{}`, `tcp_lz4/{}_{}`, `{}_block_duration`, `{}_backlog_from_node`, `{}_begin_block_to_commit`, `tokio_spawn_forever_scheduled`, `handle_request_rate_limiter`, `proposer` and `vote_abci_digest` (the literal `RE-017-node115-digest-quorum-owner` already names). Five sites pass `esi = 1` (the `+0x25d` byte in #5839): `tokio_spawn_forever_scheduled`, both name-passed-in sites, `tcp_lz4/{}_{}` and `{}_backlog_from_node`.

## Evidence 2: 68 record calls, 52 through constructor-site getters

The census of `FF15` calls through `0x64e1010` is exactly 68, as #5045 counted. At 52 sites the observer pointer is the return value of the nearest preceding direct call (`call rel32`, then `mov rdi, rax`, bytes `4889c7`). Each such callee is a function whose FDE starts at the callee and contains one of the constructor calls above. In all 67 sites with a decodable Location, no instruction writes `rdx` between the Location `lea` and the record call (checked over `record-sites.objdump.txt`).

| Calls | Getter (constructor name) | Location | Record calls |
| --- | --- | --- | --- |
| 30 | `0x51eaff0` (`bucket_guard/{}`) | `base/src/bucket_guard.rs:118:21` | `0x5483df9`, `0x5484519`, `0x548713c`, `0x548760f`, `0x548a27c`, `0x548a74f` … |
| 11 | `0x26d4660` (`bucket_guard/{}`) | `base/src/bucket_guard.rs:118:21` | `0x2bdf803`, `0x2be0607`, `0x2be1055`, `0x2be1817`, `0x2be1da7`, `0x2be6b85` … |
| 8 | `0x3704070` (`bucket_guard/{}`) | `base/src/bucket_guard.rs:118:21` | `0x422a558`, `0x422ab41`, `0x422c0de`, `0x422c6d8`, `0x422cea1`, `0x422d37b` … |
| 3 | not a direct-call return | `l1/src/abci/abci_hash.rs:28:37` | `0x2bb38a6`, `0x548d9a6`, `0x548dbb6` |
| 2 | not a direct-call return | `node/src/abci_latency_sampler.rs:60:41` | `0x5a34daf`, `0x5a6e8f8` |
| 2 | not a direct-call return | `node/src/consensus/execution_state.rs:155:30` | `0x2af7792`, `0x4dff810` |
| 1 | `0x4770930` (`bucket_guard/{}`) | `base/src/bucket_guard.rs:118:21` | `0x478079b` |
| 1 | `0x4da5d60` (`{}/{}/{}`) | `node/src/group_and_seq_sampler.rs:169:10` | `0x5b299ec` |
| 1 | `0x4da7e20` (`{}/{}/{}`) | `node/src/group_and_seq_sampler.rs:169:10` | `0x5b2a24c` |
| 1 | not a direct-call return | `base/src/lu.rs:328:38` | `0x15ed5e9` |
| 1 | not a direct-call return | `base/src/lu.rs:336:34` | `0x15ed63a` |
| 1 | not a direct-call return | `net_utils/src/tcp/lz4_stats.rs:68:18` | `0x47858c4` |
| 1 | not a direct-call return | `node/src/abci_latency_sampler.rs:70:38` | `0x51c9b84` |
| 1 | not a direct-call return | `node/src/abci_latency_sampler.rs:73:48` | `0x51c9c12` |
| 1 | not a direct-call return | `node/src/consensus/latency_samplers.rs:38:21` | `0x57e765a` |
| 1 | not a direct-call return | `node/src/consensus/validator_set.rs:263:33` | `0x595dc04` |
| 1 | not a direct-call return | `node/src/node.rs:434:45` | `0x5a6edbe` |
| 1 | not a direct-call return | none decoded | `0x154953b` |

- 50 of the 68 record calls share one Location, `base/src/bucket_guard.rs:118:21`, through four `bucket_guard/{}` getters (`0x51eaff0` 30, `0x26d4660` 11, `0x3704070` 8, `0x4770930` 1). Inference: one bucket-guard recording line, monomorphized or inlined into many callers.
- `0x51eaff0` is the record adapter that `RE-001-listener-observer-record-slot-115` maps (an existing index returns base plus index × 608). 608 = `0x260`, which fits an observer whose highest known fields are `+0x25c`/`+0x25d` (#5839, #5841). Inference: this getter returns a slot in a table of observers.
- `0x4da7e20` is the block-step host of #4460 (`seq_task/l1/<step>`), and `0x4da5d60` is its sibling. Both use template `{}/{}/{}` and record with Location `node/src/group_and_seq_sampler.rs:169:10`, the specialization #4718 named.
- The other 16 record calls take the observer from a register, a field (`[rbx+0x8]`, `[r12+0x8]`, `[rbx+0x4c0]`), a stack slot or a static (`lea rdi, [rip+0xba0130]` at `0x595dc04`). Their Locations name `base/src/lu.rs`, `l1/src/abci/abci_hash.rs`, `net_utils/src/tcp/lz4_stats.rs`, `node/src/abci_latency_sampler.rs`, `node/src/consensus/execution_state.rs`, `node/src/consensus/latency_samplers.rs`, `node/src/consensus/validator_set.rs` and `node/src/node.rs`. One call (`0x154953b`) has no `lea rdx` in its window.

## Limits

Not mapped: the values that fill each template's `{}` slots (the formatter pairs), the constructor's `xmm0` argument, which observer each register-sourced record call uses, the callers of the two name-passed-in sites and of the getters, and what `0x1546570` exports (separate work). Locations are what the binary passes. That they are the recording source lines is an inference.
