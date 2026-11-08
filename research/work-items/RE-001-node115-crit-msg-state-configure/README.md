# RE-001: node115 crit_msg_state configuration write path

Component: foundation (`base/src/crit_msg.rs`). One bounded question: what does the configure body `0x150ad00`, reached through RELATIVE slot `0x64e0b38`, write into the `crit_msg_state` lazy mutex, and with which inputs?
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes.
Base main: `0781ce048`.

## Findings

**Chain selection.** `0x150ad00(chain dil, role rsi/rdx)` dispatches the chain byte through the unbounded jump table `0x465704`. Value 0 (`Local` in the Chain Display name table `0x4820f4`) goes straight to the epilogue, so no state is written. For 1/2/3 (`Sandbox`/`Testnet`/`Mainnet`) it reads the configuration global (slot `0x64e0b40` → `0x64f0210`, Once dword `+0x1c0`) and clones two optional strings (capacity, pointer, length; None niche `0x8000000000000000`):

| Chain | First field | Second field |
| --- | --- | --- |
| Sandbox | `+0xd0` | a second clone of the first |
| Testnet | `+0xb8` | `+0xa0` |
| Mainnet | `+0xa0` | `+0xa0` |

Testnet and Mainnet converge at `0x150af2f`. Sandbox gets its second field at `0x150b070` (`mov rsi, r15`, the first clone). The body then calls the address lookup `0x1562670` (slot `0x64e0b48`). It is the only FDE that references `hostname -I | awk '{print $1}'`, `ifconfig.me`, `api.ipify.org` and `icanhazip.com`. The call fills two address Strings, and the body packs a 0x50-byte record: both fields at `+0x00`/`+0x18`, then `&role`, `&chain` and the two address Strings at `+0x30..+0x48`.

**Lazy mutex.** `0x14c2b50(object 0x64efeb8, record)` checks the object's state (slot `0x64dffe0` → `0x154cd10`). If that check returns nonzero, it prints `lazy mutex: {}` with the object name, frees the record's Strings and returns 1. Configure then logs `crit msg initialization not applied` at `crit_msg.rs:471`. If the check returns zero, the record is copied, `+0x50` is set to the object, and the wrapper `0x154c4e0` is called. That wrapper always returns 0 and calls the payload `0x15444d0` at `0x154c66e`/`0x154c682`. The object is laid out as initializer `+0x00` (RELATIVE → default `0x150c020`, studied in #2191), name `crit_msg_state` `+0x08`/`+0x10`, lock byte `+0x48` and a 0x198-byte Option value `+0x50`.

**Payload writes, under the lock (`lock cmpxchg 0→1`, futex slow paths through slots `0x64e01f8`/`0x64e0f38`).** If the value is None, the payload runs the initializer and copies 0x198 bytes. It then sets value `+0x190` to 1 and formats the template `0x43566f`, which reads `{role} chain={chain} ips=[{addr} {addr}]`, into value `+0x00`, freeing the old buffer. It *moves* record fields 1/2 into `+0xf0`/`+0x108`, freeing old Some values. Next comes the assertion `!(self.is_production && self.crash_on_crit)` at `crit_msg.rs:648:13`. Because `+0x190` was just set, the test reduces to: a nonzero `+0x191` panics while the lock is held. Last, the payload clones the role, maps `' '` to `'_'` (SIMD for 16- and 8-byte chunks, then a scalar tail; other bytes, tabs included, are unchanged), and stores it at `+0x18` before unlocking. The default `0x150c020` writes the same offsets: `+0x190` word 0, the label `N/A (non-production)`, None at `+0xf0`/`+0x108`, and an empty tag at `+0x18`.

The `is_production` / `crash_on_crit` names come from the assertion text. They are inferences, and so is the role of the two cloned fields.

## Corrections to merged packets

- `RE-005-node115-key-consumers` says "the lookup callee only logs" and that `0x154c4e0`'s "verdict can only produce a log line". In fact the zero branch of `0x154cd10` writes `crit_msg_state` through the payload. The `al` that configure tests comes from the `0x154cd10` check, not from `0x154c4e0`, which always returns 0 (as `RE-001-node115-zero-result-wrappers` established). The "key triple" is the role &str, which is formatted and turned into a tag. RE-005 also lists one reference field per chain, but each chain selects two.
- This packet closes the step that `RE-001-node115-zero-result-wrappers` names next for the `0x15444d0` payload and its caller argument layout. `0x1544b00` remains open.
- Open #4462 maps the single `crit_msg.rs:648` location edge inside this payload; here that edge is one obligation of the whole body.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes |
| --- | --- | ---: |
| payload | `0x15444d0..0x154498b` | 1211 |
| configure | `0x150ad00..0x150b305` | 1541 |
| lazy_mutex_run | `0x14c2b50..0x14c2c47` | 247 |
| chain_display | `0x1778c60..0x1778cca` | 106 |
| str_display | `0x15ebba0..0x15ebbb3` | 19 |
| string_display | `0x15433a0..0x15433b4` | 20 |

That is 6 complete FDEs, **3144 bytes / 718 instructions**. Two support windows are also retained, the wrapper calls `0x154c669..0x154c687` and the default writes `0x150c0fc..0x150c16e`, without claiming those bodies. GNU and LLVM decode every byte with identical instruction boundaries. `verify.py` authenticates the image and then binds FDE/CIE records, body hashes, 230 instruction obligations (70 with branch or RIP targets), 17 RELATIVE slots, the `memcpy` GLOB_DAT, literals and both jump tables. It decodes the 25 layout claims from operand displacements. A capstone-qualified census covers incoming calls and RIP-relative users of the object, the Chain Display slot and the IP strings. `controls.json` records **291 rejected corruptions**: 22 semantic mutations plus byte flips of every obligation, slot addend, literal and table. They run with the image, body and export guards bypassed. `records.json["relations"]` projects the per-chain selection, the label, assertion and role tag from the decoded offsets. It is not an emulation.

```sh
python3 research/work-items/RE-001-node115-crit-msg-state-configure/export_disassembly.py
python3 research/work-items/RE-001-node115-crit-msg-state-configure/verify.py --controls
python3 -m unittest tests.test_node115_crit_msg_state_configure -v
make doctor verify test catalogue-check reproduce
```

The exporter needs GNU `objdump`/`readelf` and `llvm-objdump` on PATH and runs on a private non-executable copy. `verify.py` needs Capstone. `make verify`, `catalogue-check`, `reproduce` and the focused suite pass; the full `make test` does not finish on this host (per-file reload of the ~101 MB image across 1132 files), and `test_run_tests`'s 5 failures are a Python 3.9-vs-3.11 unittest id-format mismatch in files this change does not touch. Tool versions and gate results are in `validation.json`.

## Unresolved

Runtime contents of the configuration fields and address Strings; `0x154cd10`'s state predicate; the `0x1562670` lookup internals; what reads the label, fields and tag later; the Once-forced paths through `0x150ae40`/`0x150af89`; the instrumentation branch of `0x154c4e0`; `0x1544b00`. Not claimed: Rust reconstruction, byte equivalence, live behaviour or progress gates. The capture was never executed or emulated. ELF/export reader structure follows `RE-001-node115-critical-message-repeat-throttle` (credited in `verify.py`); all measurements are new.
