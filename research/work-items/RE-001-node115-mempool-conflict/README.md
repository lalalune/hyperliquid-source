# RE-001: node115 mempool existing-key conflict disposition

- Component: consensus; bounded mempool admission guard, not complete mempool reconstruction.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no inferred or unlicensed source consulted.
- Question: does an already-found key whose stored 32 bytes disagree with the incoming 32 bytes take the same local fallback as a missing key?
- Result: **no**. Both equal and conflicting found entries bypass the fallback call. A conflicting entry first takes the diagnostic-call arm. This is a local control-flow observation conditional on normal helper returns, not a claim that helper side effects are closed.

## Measured boundary and source binding

`0x2e1fe30..0x2e20047` is one complete unwind-described FDE: **535 raw bytes, 117 decoded instructions**. `records.json` retains its complete FDE/CIE record, file mapping, body hash, bytes, every direct/indirect call and branch, source Locations and relocations. `native.asm` is the complete GNU export. An unwind range is not proof that every semantic operation or split cold block is recovered.

The two RIP-relative Location arguments are `0x6451c58` at `0x2e20007` and `0x6451c70` at `0x2e2002e`. Their `R_X86_64_RELATIVE` records bind them to the full `node/src/consensus/mempool.rs` string with source lines **818:17** and **826:44**, respectively. The former accompanies the disagreement diagnostic path; the latter accompanies the miss fallback. Diagnostic paths establish a bounded source association, not original function or field names.

## Observations

The incoming registers used in this local function are object pointer RDI, an eight-byte key RSI, and a pointer RDX to 32 incoming bytes. Native object/pointer validity and established collection invariants are preconditions; no public ABI is claimed.

1. `neg` of the word at object `+0xc0` and `jno` distinguish precisely `0x8000000000000000` from other 64-bit values. Only that sentinel reaches the inline tree-shaped traversal. The other arm calls `0x24c5f50` on object `+0xc0`, with the incoming key's stack address. The helper's behavior remains unmeasured; the caller locally treats AL bit 0 set or an unsigned RDX value at least object `+0xd8` as a miss.
2. The inline traversal compares the full unsigned incoming eight-byte key with stored keys, using `seta` / `sbb` to distinguish greater/equal/less. A zero node pointer, or exhausted depth after the child transition, reaches `0x2e20027`. Equality reaches `0x2e1ff22` and computes a pointer to a 32-byte associated value. The collection's original Rust type, tree invariants and construction remain unknown.
3. The non-sentinel arm accepts only the caller-local hit condition described above. It adds object `+0xd0` to the helper's RDX, conditionally subtracts the capacity-like word at `+0xc0` once, and selects a 40-byte row plus eight bytes at object `+0xc8`. The ring/collection identity and helper index guarantee remain inferred, not established semantics of the helper.
4. Both local hit paths converge at `0x2e1ff29`. Two 16-byte loads from the found value and two from incoming RDX feed two `pcmpeqb`s, `pand`, `pmovmskb`, and comparison against `0xffff`. Thus the final flag is equality of **all 32 bytes**; it cannot be satisfied by matching just one half. This is byte equality, not a proof that those bytes are any particular hash algorithm or transaction ID.
5. Full equality takes `je 0x2e2003a`, the common epilogue. Disagreement builds diagnostic arguments and calls the relocated slot `0x64e0b18` at `0x2e20018`. On return, an unconditional jump also reaches that epilogue. Neither local hit arm reaches the fallback call at `0x2e20035`.
6. Miss paths call `0x2cacdb0` with object `+0xa0`, the incoming key, incoming payload pointer and the line-826 Location. This packet calls it the **miss fallback**, not a proven insertion routine: its state changes, return value and error behavior are not yet measured. Likewise the diagnostic call's ultimate behavior is unresolved; it could fail to return.

The distinction is useful for reconstructing admission semantics: treating disagreement as absence would introduce an extra fallback call absent from the observed control flow. This packet does not implement an admission API or replace either unresolved helper.

## Reproduce and controls

From the repository root, on Linux x86-64, Python 3.12.3, Capstone **5.0.7**, GNU objdump **2.42**:

```sh
python3 tools/node115_mempool_conflict.py --write
python3 tools/node115_mempool_conflict.py
python3 -m unittest discover -s tests -p test_node115_mempool_conflict.py -v
```

Only `--write` updates the retained static exports. The default verifies exact replay. The captured node is only read; no native target code, emulation, network or chain operation occurs. Eight checks pass: retained target/FDE/Locations, wrong-target rejection, truncation rejection, and five structural corruption controls. The controls invert the equality exit, redirect the disagreement exit toward the fallback, substitute the low payload half for the high one, replace AND with OR, and change unsigned miss-bound comparison to signed. They are rejected at decoded instruction boundaries, not only by the outer artifact digest.

`records.json` also preserves direct-helper FDE boundaries and relocation records for the diagnostic/format callback slots. These are dependency leads, **not** measured helper bodies. No closed-caller census, runtime behavior, independently authored Rust, compiled source/target comparison or raw-equal/normalized-only/unmatched comparison denominator is claimed. The raw export denominator is one FDE / 535 bytes / 117 instructions. All component gates remain false; no progress counters are edited.

Next question: measure `0x2cacdb0` and its mutation/error closure to determine exactly what the locally missed key does, while preserving the found-entry early exits established here.

Native text exports trim trailing whitespace only; instruction bytes, operands and addresses are unchanged.
