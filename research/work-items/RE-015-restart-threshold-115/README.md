# RE-015: restart threshold through a resumed poll

On the selected node #115 restart continuation, a configuration-rooted numeric threshold controls whether a saturating counter and a pending message are retained, and resuming the later wait bypasses the counter increment.

- Component ID: `constants` (RE-015; the downstream poll is studied only as a consumer).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was consulted for leads only and no reference code was copied.
- Claim status: static observations below; the roles of the configuration fields, the poll and the message are inferences. The original source names and live values remain unresolved.
- Scope included and excluded: one selected resumed path, its threshold reader and selected numeric parser, both pending exits and selected unwind landings. This is not the entire restart state machine, complete filesystem/JSON behavior, or the global-configuration component gate.

## Reproduce

Run from the repository root with the authenticated #115 capture present. The collector checks its whole-file SHA-256 before parsing. It imports `tools/elf_index.py` and `tools/fde_extents.py`, excludes `SHT_NOBITS`, checks selected fixed instruction windows, and reads relative operands, relocations and LSDA call-site bytes directly. It invokes no external program. Python 3.12.3 on Linux x86-64 was used; Python's standard library is the only dependency. The generated files do not contain a clock value, environment-dependent path, or disassembler output.

```sh
python3 tools/re015_restart_threshold_115.py --out research/work-items/RE-015-restart-threshold-115
python3 -m unittest tests.test_re015_restart_threshold_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-restart-threshold-115 && sha256sum -c MANIFEST.sha256)
```

For the determinism control, replace the placeholders with distinct empty writable directories. Both commands and the focused tests were also run with only Python on `PATH`.

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re015_restart_threshold_115.py --out <tmp-dir-one>
PYTHONHASHSEED=984 TZ=Pacific/Honolulu python3 tools/re015_restart_threshold_115.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

An optional independently hashed comparison with the historical capture can be reproduced when that separate file is available. It prints the comparison and does not alter the generated #115 evidence format.

```sh
python3 tools/re015_restart_threshold_115.py --out <tmp-dir-three> --compare-94 references/can1357-hl/bin/hl-node-mainnet-new
```

GNU objdump 2.42 was used only for human inspection of bounded instruction ranges. No objdump text is an input to the generator or tests, and no captured executable, network service, process, key or live user state was accessed.

## Evidence

All code and data addresses below are linked ELF virtual addresses before load bias. Generated records also provide section-derived file offsets and actual bytes. `functions.tsv` and `bodies.tsv` contain the nine selected unwind-described FDE extents and their full bodies; FDEs do not prove a complete function census or source-function boundaries. `windows.tsv` gives 58 checked byte windows; `transfers.tsv`, `rip-references.tsv`, `relocations.tsv`, `dispatch.tsv`, `data.tsv` and `exceptions.tsv` record independently decoded operands and tables. No operand masks are used.

### Entry and the two suspension points

The poll entry `0x2aeaef0` indexes a relative table using byte `+0x71`; on the selected value 3, slot `0x6041f8` resolves to `0x2aeb1cd`. This code indexes a second relative table using byte `+0x120`.

| Selected nested value | Target | Bounded observation |
| --- | --- | --- |
| 3 | `0x2aefee7` | Calls `0x2a91280`; a set low result bit branches to the pending return with nested value 3. |
| 4 | `0x2af016e` | Polls the later wait directly; this entry is after the counter update and threshold call. |

The first helper passes the 16-byte data slice `async_wait_inner` at `0x451330` into a construction path. If its lower poll returns a nonzero marker, `0x2a913d0..0x2a913e6` stores its local tags as 3 and returns 1; its zero-marker path returns 0 after selected cleanup. The parent stores 3 or 4 into the nested state and 3 into `+0x71`, then returns 1. Thus, conditional on those selected state values and ordinary calls, a later wait's pending/resume cycle does not repeat the threshold read or the counter increment. No complete state-table domain or execution schedule is claimed.

### Setting, parser and decision

The seven-byte RIP-relative instruction at `0x1562329` points to the **complete** 44-byte entry at `0x4315ea`, consisting of `c0 29`, the 41-byte suffix `/hyperliquid_data/n_restarts_to_page.json`, and a zero terminator. A relocation binds slot `0x64e0918` to the configuration object at `0x64f06c0`. After its guard is ready, wrapper `0x1562300` passes object offset `+0x18` through a string adapter to the formatter, then calls reader `0x1501b80`. The formatter and actual root are boundaries; neither the live resulting path nor the rendered placeholder is assumed.

The reader calls path helper `0x1500c10`. It checks input length before comparing the first two bytes with `~/`; that prefix advances the input by two and selects a configuration-object-based formatting path, while other inputs take the copy path. Empty input and allocation failure have separate branches. After a path predicate, the reader has a missing-path diagnostic route and two component-dependent read routes. The selected text route treats only the word `0x8000000000000000` as the read-error sentinel, invokes numeric parser `0x1574a60` on the normal read-result path, and treats parser result tag 1 as an error. Under normally returning diagnostics and cleanup, these error routes return zero. A successful numeric result is carried in the second result register. The exact component helper and complete text/binary input grammars remain boundaries.

For the integer-shaped ASCII subset, parser `0x1574a60` skips only bytes 9, 10, 13 and 32 at the selected whitespace gates, and `0x1575d40` rejects an additional digit after a leading zero. Its accumulation uses immediate `0x1999999999999998`: a prefix at most that value is safe to multiply by 10; the next prefix value is admitted only for a digit at most 5. On overflow it takes a separate floating/error helper boundary. `0x15759f0` supplies distinct integer, floating and error tags. The selected unsigned-integer consumer rejects the negative and floating tags; this includes `-0`. These observations support the bounded integer-only model in the tests, not a claim that every other JSON form has been reconstructed.

At `0x1562372`, the wrapper executes `cmp rax, 1; adc rax, 0`: zero becomes one, while every nonzero 64-bit word remains unchanged. The caller compares its post-increment `+0xb8` word **unsigned** against that returned threshold:

| Condition after saturating increment | State before the later wait |
| --- | --- |
| counter below threshold | `+0x11e` remains 1 and `+0xb8` retains the incremented value. |
| counter equal to or above threshold | `+0x11e` becomes 0, the message-like triple is conditionally released, and `+0xb8` becomes 0. |

The `+0xb8` increment saturates at `u64::MAX`. Independently, for an **ordered** comparison with the captured binary64 constant 600.0 at `0x459568`, a value greater than 600.0 clears `+0xb0`; otherwise that counter increments with the same saturation rule. The arithmetic converting a duration and the complete meaning of either counter are not claimed.

### Failures and unwind

The selected LSDA call-site table associates the first poll call at `0x2aefef6`, threshold call at `0x2af011a` and later wait call at `0x2af017d` with landings `0x2af056a`, `0x2af047a` and `0x2af04dc` respectively. The latter two join cleanup that tests `+0x11e`, conditionally releases the associated allocation, clears the flag, performs further selected cleanup, stores state 2 and resumes unwinding. The wrapper's call to the reader is covered by landing `0x15623b5`; the reader's selected text-decoder call has landing `0x1501efc`. `exceptions.tsv` decodes 247 call-site rows, but does not decode action/type tables or prove every exception outcome.

### Historical context and inference

The retained #94 evidence identifies the two original complete entries `/static_config` at `0x1ef5f5` and `/cham` at `0x1fc0ec`, with references at `0x164fbae` and `0x164f840`. Their corresponding #115 entries are `0x4401ef` and `0x44ab69`, with references at `0x177840e` and `0x17780f3`. Those #115 loader/selector functions are already covered by open configuration packets and are not selected for analysis here. The optional comparison authenticates the historical capture with SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, checks both releases' complete entry bytes and relative references, and preserves the release-specific coordinates.

The same comparison checks the single prior `NvTestnet` descriptor: index 32 in the recorded #94 table and index 33 in the recorded #115 table. Descriptor positions alone do not prove a classifier or fallback; those remain prior-work boundaries. It also independently checks the restart-setting entry at #94 `0x1de68f` and #115 `0x4315ea`, plus identical floor instruction bytes at #94 `0x13ca072` and #115 `0x1562372`. The new state transition and selected #115 numeric branches are derived from #115 bytes, not relabelled #94 findings. This packet does not resubmit the historical 76-name table.

The path, string and restart labels are supported by data and call context but remain inferred roles. In particular, the observed `+0x18` configuration field is separate from the previously reported name byte at `+0x48`; this packet does not claim that the default name selects the threshold or that an alert is actually sent.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo graph, lockfile, two-build result, runtime fixture, raw/normalized implementation comparison, helper closure or whole-ELF comparison is claimed. `decimal_integer_model` and `threshold_step` are explicitly conditional synthetic models, not execution of the node. The tests compare the integer-only model against Python's independent JSON parser for 1,613 selected byte strings and check 65,536 counter/setting pairs and all 65,536 two-byte path prefixes, plus full-width boundaries and malformed-input controls. Corrupt input hashes, FDE-range and instruction-window bytes, a branch, table displacement, relocation, template terminator, descriptor length, LSDA header, invalid mappings and out-of-range model values are rejected.

## Results and limitations

The #115 packet contains 9 selected FDEs totaling 26,650 bytes, 58 fixed windows, 34 selected transfers, 11 RIP-relative references, 11 data entries, 5 selected table entries, 4 relative relocations and 247 LSDA call-site records. These are evidence-item counts, not component coverage. All 32 focused unittest methods passed with zero skips; two regenerations with different hash seeds and time zones matched byte for byte with binutils absent from `PATH`. Artifact hash/signature verification, catalogue consistency and input reproduction passed. Repository-wide unittest discovery, hosted CI and target execution were not run.

The formatter, path/component parser, file I/O, diagnostic and drop internals, binary input path, asynchronous lower poll, later wait implementation, floating conversion, exception action tables, all original inputs, and complete poll state machine remain unresolved. The provided open-PR snapshot lists files but not every contribution's byte records, so another address-level overlap check is required before forwarding. No component gate is advanced. Next question: validate which independently established producer initializes `+0xb8` and the normal lifetime of `+0x11e` across all poll exits without selecting an owned helper.
