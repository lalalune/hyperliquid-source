# RE-007: #115 asset-name lookup result

This static packet answers the first part of the next question in [the asset-registration caller packet](../RE-007-node115-asset-registration-caller-name-rules/README.md): what the previously unanalysed helper `0x421a8b0` computes from its supplied bytes. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Addresses are virtual addresses. Target code was not executed or emulated.

## Observations

For valid inputs and ordinary returns, `0x421a8b0..0x421a9cc` receives an output pointer, byte pointer, length and context in `rdi`, `rsi`, `rdx`, `rcx`. It reads a count at context `+0x10`, a row base at `+8`, and, when the count is nonzero, multiplies context `+0x50` by 10,000 with an overflow branch. Rows are addressed at 0x20-byte increments. Each row's length at `+0x10` is compared with the input length; for equal lengths the imported `bcmp` compares input bytes with the pointer at row `+8`. On the first equality the helper stores `10,000 * context[+0x50] + row index` at output `+8` and writes the word `0x1a2` at output `+0`. The index increments per scanned row and an unsigned wrap branches to a separate failure path. These are raw observations; asset identity and data structure invariants are not proved here.

If the scan finds no equal row, and assuming allocation and copying return normally, the helper writes output word `0x68`, the input length at `+8` and `+0x18`, and a copied buffer pointer at `+0x10`. For zero length it uses raw pointer value 1 and does not allocate or copy. Large lengths, allocation failure and panic paths are outside the ordinary-return claim. The verifier binds the compare and copy calls to dynamic symbols `bcmp` and `memcpy`; it does not prove alternate runtime symbol bindings.

In selected prior caller `0x447d760`, `0x447da3f` calls through relocation `0x64e69b8`, whose pinned relative relocation names `0x421a8b0`. The caller passes its selected pointer and length and checks the word at the temporary result: `0x1a2` selects the qword at result `+8`; any other word takes a different branch. The prior packet already traced the suffix validation and remaining caller behavior; this packet adds the helper's row search and no-match result, not a second claim over the caller.

Example: assuming valid rows, no arithmetic overflow and the usual `bcmp` contract, if context `+0x50` is 3 and the first matching row is index 2, the selected success qword is 30002. This is a conditional consequence of observed arithmetic, not a live lookup.

## Evidence and limits

`instructions.tsv` contains the complete helper disassembly and the selected caller window. `verify.py` checks the authenticated target digest, two indexed FDEs and their body hashes, 88 instruction records, 32 explicit byte pins, five relative targets, three relocations, two import names and seven corruption controls. It does not interpret code. The previously catalogued `RE-001-node115-loc-edge-421a9a4` covers the overflow location edge only; it does not establish this scan or result layout. The search's input provenance beyond the credited caller, name grammar, row ownership, dynamic interposition, all panic behavior, `0x3bcb6c0`, and exchange-level meaning remain unresolved. No component completion is claimed.

Reproduce from the repository root with `PYTHONPATH=tools python research/work-items/RE-007-node115-asset-name-lookup/verify.py` using Python with Capstone installed.
