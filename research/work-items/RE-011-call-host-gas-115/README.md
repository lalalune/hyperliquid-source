# RE-011: CALL-family host gas charging and EIP-7702 delegate access on node 115

This packet lets a reconstruction implement the shared account-access and gas-charging step of the node #115 CALL, CALLCODE, DELEGATECALL and STATICCALL handlers (alternate host `0x546c330` and ordinary host `0x4335cf0`) as one executable function: value-transfer charge, cold-access hint, empty-account test, new-account surcharge, 23-byte delegation designator resolution with a second account load, refund-first drawing of the extra cost, the 63/64 forwarding cap with stipend, and the exact order of frame writes, reference-count updates and abort points. It was proven against the real machine code on 12,800 generated cases.

- Component ID: `evm` (RE-011 EVM fork and RPC adapter; no progress gate is requested).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: workspace at origin/main; unlicensed reference tree `references/can1357-hl` used only as a clue source, nothing copied. #94 results were not used.
- Claim status: the code bytes, relocations, FDE extents, branch outcomes and the case-by-case agreement below are observations; field names (gas, refund counter, cost table, designator) are inferences from the observed use; the loader, code-preparation helper and drop slot are stubbed boundaries and are unresolved.
- Scope included and excluded: the two 0x870-byte host bodies, the cleanup helpers `0x563e0e0` / `0x4357560` (evaluated for real). Excluded: the loaders `0x5463980` / `0x4323870`, the code-preparation helpers `0x54793e0` / `0x433c700`, the lazy initialiser, the Arc drop routine behind slot `0x64e4fa8`, the eight handlers that call these hosts (already mapped by RE-021-call-host-115) and any real account data.

## Reproduce

From the repository root with the authenticated node #115 artifact present:

```sh
python3 tools/re11_call_host115.py --out research/work-items/RE-011-call-host-gas-115
python3 -m unittest tests.test_re11_call_host115
python3 tools/artifacts.py verify
(cd research/work-items/RE-011-call-host-gas-115 && sha256sum -c MANIFEST.sha256)
```

Independent regeneration with no programs on `PATH`:

```sh
python_exec="$(command -v python3)"
PATH= PYTHONHASHSEED=1 TZ=UTC "$python_exec" tools/re11_call_host115.py --out <tmp-dir>/one
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$python_exec" tools/re11_call_host115.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
```

Python 3.12.3, Linux x86-64; GNU objdump 2.42 was used only to read instructions while writing the model. The tool imports the repository evaluator `tools/re11_transient_storage115.py` (Image, Machine, Stream) and the shared resolvers it uses (`tools/elf_index.py`, `tools/fde_extents.py`); it calls no external program, checks the full input SHA-256 before ELF parsing, never executes the node and never consumes live state. Generation is deterministic (SHA-512 streams, no clock, no randomness) and holds one case at a time.

## Evidence

Addresses are ELF virtual addresses before load bias; `functions.tsv` lists both FDE extents (read from `.eh_frame`) and the role addresses.

| Host | Start | End (exclusive) | Loader | Code prep | Cleanup | Lazy init |
| --- | --- | --- | --- | --- | --- | --- |
| alternate | `0x546c330` | `0x546cba0` | `0x5463980` | `0x54793e0` | `0x563e0e0` | `0x5b084ff` |
| ordinary | `0x4335cf0` | `0x4336560` | `0x4323870` | `0x433c700` | `0x4357560` | `0x435059c` |

Observed behaviour (identical in both hosts; the only differences are RIP-relative operands that resolve to the corresponding sibling targets):

1. `ecx != 0`: gas (frame `+0x188`) minus cost `+0x78`; borrow gives result byte `0x20`, tag `2` at result `+0x30` and no frame write; otherwise the reduced gas is stored.
2. The loader is called with `(vm+0x270, vm+0x398, address word, hint)` where hint is `spec(+0x1a9) >= 7 && gas < cost[+0x80]`. Status byte `2` returns the `0x20/2` result.
3. Emptiness: vm byte `+0x396 > 2` uses the 32-byte code hash (the constants at `0x4537f0` and `0x452020` form the empty-code hash; an all-zero hash also qualifies), account words `+0x28..+0x48` and nonce `+0x68`; otherwise flag byte `+0x8c` bit 3 set and bit 2 clear.
4. The code object is `account+0x70` (refcount at `+0`, bytes pointer `+0x38`, length `+0x40`, kind `+0x7c`); a null pointer counts the lazily initialised global object instead. A reference count increment that ends zero or negative without signed overflow reaches `ud2`.
5. New-account flag (`r8b`) with an empty account: cost `+0x88`, or zero when `spec >= 3` and the low value bit is clear. Otherwise a code object of kind 1 is a designator: length `<= 0x16` panics through slot `0x64df570`; bytes 3..22 become the delegate address, cost `+0x90` is added (carry panics through `0x64df520`), exceeding the remaining gas is an out-of-gas result, `cost[+0x80] + total` is the hint threshold of the second load, and the delegate's code hash and code object replace the first (the first reference is released, dropping at zero).
6. Total deducted from gas (stored immediately). `cost[+0x158]` (when value flag and vm byte `+0x265`) is taken from frame `+0x190` first; the shortfall is taken from gas, the saturating signed total at `+0x198` grows by the full amount, and `+0x190` is zeroed. For `spec > 1` the requested gas is capped at `gas - gas / cost[+0x70]` (zero divisor panics through `0x64df878`). Gas is reduced by the forwarded amount; with the value flag the stipend `cost[+0xc0]` is added with saturation to `u64::MAX`.
7. Result slot: `+0` code object, `+8` forwarded gas, `+0x10..+0x30` code hash, `+0x30` byte `rbx != 0`.

`branches.tsv` counts, for every conditional jump of both bodies, how often each outcome occurred over 1,500 coverage cases. `cases.tsv` keeps every second model case (host, spec, gas, value flag, new-account flag, request, code-object kind, result, gas after, forwarded gas, flag, event count); the remaining cases are regenerated by the tool.

## Implementation and comparison

`tools/re11_call_host115.py` holds (a) the decoder/evaluator extension (lock prefix, `por`, `movmskps`, `not`, `div`, signed jumps), (b) `model()`, a standalone Python function of one case that returns the result slot, frame writes, reference-count cells and ordered event list (loader calls, code-preparation calls, drops, lazy init), and (c) the harness that lays out frame, vm, cost table, two accounts and three code objects in evaluator memory, stubs the boundaries with recorded arguments, runs the real bytes and compares every field. 12,800 cases (6,400 per host) produced 0 mismatches. Controls: 120 negative controls, all 120 detected: 17 deliberately wrong model variants per host (wrong error byte, doubled increment, spec threshold shifts, strict/non-strict compares, unsaturated adds, 1/32 instead of 1/64, inverted flag, designator offset and length errors, missing stipend, skipped drops), inversion of every conditional jump of the real bytes (26 jump inversions that no pool case can expose are listed in `undetected-controls.tsv` and not counted: 13 jumps per host sit in code that only runs when the local slot at `rsp+0x118` is nonzero (never set), in the unused emptiness flag of the delegate, or in unwind landing pads; this grouping is an inference about why no case can expose them) and a corrupted code byte.

## Results and limitations

`measure.json` holds the counts used here. The model matches the real instructions for both bodies, including the abort points: out-of-gas results, three arithmetic panics, the division-by-zero panic, the short-designator panic and the reference-count `ud2`. Limits: the loader and code-preparation helper are not reconstructed, so account contents, the status byte and the code-object preparation are inputs, not results; the meaning of the status bit 0 (cold access) and of the frame counters are inferences; the global lazy object is modelled only by its pointer and state word; no real bytecode or chain state was used.

Next question: reconstruct the loaders `0x5463980` / `0x4323870` (they produce the status byte and account pointer consumed here) and the code-preparation helpers `0x54793e0` / `0x433c700`, then connect them to this host model.
