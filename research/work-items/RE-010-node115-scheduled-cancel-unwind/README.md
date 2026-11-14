# Scheduled-cancel expiry: selected unwind cleanup

Target Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. This is partial HL115-061 / RE-010 static research. The captured executable was not run or emulated.

The expiry scanner increments the selected entry's counter and clears its date before invoking cancellation for collected keys. If selected downstream calls unwind, the recorded local landing pads clean temporary objects and resume unwinding; the driver's landing pad frees the collected key vector and resumes. These selected instructions do not restore the entry's count or date. This is a local mutation and cleanup statement, not proof of an eventually committed state or an outer transaction's rollback policy.

## Reused boundary and selected writes

[#2138](https://github.com/lalalune/hyperliquid-source/pull/2138), `RE-010-schedule-cancel-core-115`, already establishes admission, the expiry scan, selected normal-return counter/date updates, and the per-DEX/base handoff ordering. `RE-010-node115-schedule-cancel-source` independently implements the local source-side expiry predicate and mutation, explicitly excluding downstream cancellation. This packet adds the actual call-site exception-table entries and selected local cleanup flow; it does not claim the earlier scan or cancellation helpers as new.

On the selected expiry path, `0x2be2375..0x2be238b` reads the selected entry's first u64, increments it with `u64::MAX` saturation, writes it back, then writes zero to the date dword at `+8`. The scan continues collecting 20-byte keys. After the scan, `0x2be2411` calls `0x2bf9910` for each key, with raw selector 2 and flag 15. On normal return the caller advances its key cursor; no status is tested at that call site. The later date-dependent reset at `0x2be249d..0x2be24ae` is reached only on a normal continuation through the handoffs; it is not executed by the selected driver landing pad.

## Exception table and local continuation

The verifier decodes the relevant ULEB call-site tables and confirms the FDE-to-LSDA associations. It binds these exact call sites, rather than inferring unwind edges from nearby cleanup code:

| Throwing call | Selected call-site landing | Local action before resume |
| --- | --- | --- |
| per-DEX `0x22f2000` at `0x2bf9c30` | `0x2bf9dea` | cleanup stack object through `0x2c86c40`, then free the collected DEX vector and resume |
| per-DEX `0x2419810` at `0x2bf9c52` | `0x2bf9dff` | free the collected DEX vector and resume |
| base `0x22f2160` at `0x2bf9ce9` | `0x2bf9d8d` | cleanup stack object through `0x2c8a810`, then resume |
| base `0x241a3c0` at `0x2bf9d0a` | no local landing in its call-site record | propagation proceeds outside this FDE's selected cleanup |
| driver's `0x2bf9910` at `0x2be2411` | `0x2beabd1` | free the collected 20-byte-key vector if allocated, then resume |

The handoff's selected local landing paths reach `0x63f0a50`, the target's `_Unwind_Resume` PLT boundary. The driver's landing similarly reaches that boundary, either directly for an empty allocation or after the size-correct vector free. Their stated cleanup calls and frees are assumed to return normally. The internal effects of those helper calls are not reconstructed. The date/count stores occur before the driver calls the handoff; no instruction in these selected local cleanup windows rewrites those fields.

For an unwind after the recorded scan writes, this proves only that these local landing instructions do not themselves undo those writes and do not perform the later date reset. It does not prove that a callee, cleanup helper, an outer catch/transaction layer, process restart, or storage system cannot undo or supersede them. It also does not equate ordinary error return, panic, cancellation and process failure. Those are separate unresolved behaviors.

## Reproduction

The verifier authenticates the whole target digest, checks eight instruction windows (479 bytes / 109 instructions), 70 static facts and 70 altered-byte controls. It separately verifies each owner's actual FDE→LSDA pointer, decodes the ULEB call-site table and checks the selected cleanup landing or absence. Raw call-site entry bytes are retained and independently covered by corruption controls.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-010-node115-scheduled-cancel-unwind/verify.py --target /path/to/original/hl-node
```

No complete state rollback, retry, database persistence, all-DEX behavior, or network outcome is claimed. No component gate is advanced.
