# evm: reconstruct the node #115 CREATE and CREATE2 opcode handlers (both handler families) and the pending-call replacement

This packet lets a reimplementation of the HyperEVM interpreter reproduce, for every input state, exactly what the four
CREATE / CREATE2 opcode bodies of node #115 do: which status byte they return, which stack words they consume, how much gas
they charge (initcode word gas, create fee, CREATE2 hash words, memory expansion, refund-counter top-up, the 63/64 split), how
the initcode is copied into a `Bytes` value, how the 0xc8-byte create request is laid out, and how the host's pending-call slot is
replaced and the old content released. `tools/evm_create_opcodes_115.py` executes the real machine code of all six bodies on
14,000 generated states and compares every observation with one pure-Python reconstruction (0 mismatches); 50 of 50 negative
controls are detected.

- Component ID: evm (HyperEVM execution), opcode dispatch tables 0x6485ef8 / 0x6486c60 / 0x649eea0, slots 0xf0 and 0xf5
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository head at submission time (new files only); no reference-source code is copied
- Claim status: observation (bytes, tables, relocations, frame extents) plus inference (the model, checked against the executed machine code)
- Scope included and excluded: included - handlers 0x4338c10 (CREATE), 0x4339270 (CREATE2) shared by tables A and B, handlers
  0x4f07ae0 (CREATE), 0x4f07460 (CREATE2) of table C, the pending-slot helper 0x4f00920 reached by the second family, and the memory
  expansion body 0x45244c0 (GOT slot 0x64e6de0). Excluded - what happens to the queued request afterwards (the call-frame
  loop that consumes host+0xb8), the Bytes drop bodies, the allocator, the unwind landing pads, and the `Arc` slow drop. No gate is requested.

## Reproduce

Run from the repository root with the linked binary in place (Python standard library plus `tools/fde_extents.py` and `tools/elf_index.py`):

```
python3 tools/artifacts.py verify
python3 tools/evm_create_opcodes_115.py --out research/work-items/evm-create-opcodes-115
python3 -m unittest tests.test_evm_create_opcodes_115
```

The tool checks the binary SHA-256 first, never executes the binary and calls no external program. One `--out` run takes about one
minute and under 400 MB; the unit tests take about 15 seconds. All files except this README and `MANIFEST.sha256` are produced by the
tool and are byte-identical between runs (checked twice, different output folders, `diff -r`).

## Evidence

All numbers below are read from ELF bytes by the tool (section table, `.rela.dyn`, `.eh_frame` extents, code bytes).

| item | observation |
| --- | --- |
| opcode slots | tables A (0x6485ef8) and B (0x6486c60): 0xf0 -> 0x4338c10 (1625 bytes), 0xf5 -> 0x4339270 (1858 bytes); table C (0x649eea0): 0xf0 -> 0x4f07ae0 (1442 bytes), 0xf5 -> 0x4f07460 (1658 bytes) (`opcode-tables.tsv`) |
| helper | 0x4f00920 (364 bytes), called directly by the two table-C handlers with `host+0xb8` and a 0x60-byte stack image (`sites.tsv`) |
| memory expansion | 0x45244c0 (414 bytes) through GOT 0x64e6de0; evaluated as real code, not stubbed |
| GOT words | allocator 0x64df480, aligned alloc-error 0x64df490, alloc-error 0x64df498, deallocator 0x64df4a0, memcpy 0x64df508, memset 0x64df750, panic 0x64df520, divide panic 0x64df878, `Bytes` vtables 0x64df8c0 (even pointer) / 0x64df8c8 (odd) (`got-slots.tsv`) |
| instructions | every byte of the six bodies decodes (`decoded-instructions.tsv`, with a column showing whether the 14,000 cases executed it: 317/364, 361/409, 331/364, 287/319, 67/101, 106/110; the unexecuted ones are unwind landing pads, the panic tails and the allocation-failure-only paths of the second family) |

Reconstructed behaviour (`create_model` in the tool; `kind` is CREATE or CREATE2, statuses are the returned byte):

1. static byte (host+0x1a8) set -> 0x28. CREATE2 with spec byte (host+0x1a9) <= 4 -> 0x2b (CREATE has no such check).
2. fewer than three stack words -> 0x2c. Pop value (top), offset, length. Length wider than 64 bits -> 0x24.
3. The initcode starts as an empty `Bytes` (static vtable 0x6485430 / 0x649f6b8, pointer 1). Every failure after this point releases the
   current `Bytes` through its vtable slot 0x20 and returns its status.
4. Empty initcode: skip to step 8 (CREATE2 with no fourth word -> 0x2c).
5. Spec byte > 9: size limit - context byte +0x210 set: limit = word +0x218; else word +0x200 == 1: limit = 2 * word +0x208 (no limit when its top bit is set);
   else 0xc000, plus 0x4000 when context byte +0x268 >= 0xe. Length above the limit -> 0x35. Then initcode gas = ceil(length/32) * c60 (saturating at 2^64-1)
   -> 0x20 when gas is short.
6. Offset above 64 bits -> 0x24. end = offset + length (saturating for the word count); more words than the host's -> memory expansion 0x45244c0
   (words*c50 + words^2/c58, delta charged, 0x21 when short, panics at 2^59 words or c58 == 0 / on length overflow); then panics for `offset+length`,
   `offset+base`, `end+base` overflow.
7. Allocate `length` bytes (failure -> alloc error), copy from cell memory at `base+offset`, tag the data word with bit 0, pick the odd/even `Bytes`
   vtable by pointer parity, release the empty `Bytes`. CREATE2 with no fourth word -> 0x2c (releasing the new `Bytes`).
8. CREATE2: pop salt. Fee = c68 (+ ceil(length/32) * c48 for CREATE2, saturating) -> 0x20 when short.
9. Context byte +0x265 == 1: refund top-up - if host+0x190 >= c168 then host+0x198 = sat_i64(c168 + host+0x198), host+0x190 -= c168; otherwise the deficit
   comes out of gas (0x20 when short), host+0x198 gets the same saturating add and host+0x190 becomes 0.
10. Spec byte > 1: divisor c70 (zero panics), forwarded = g - g / c70 and the host keeps g / c70; otherwise everything is forwarded.
11. Request record (0xc8 bytes): tag (0 CREATE, 1 CREATE2) at +0, salt at +8, the 32-byte `Bytes` at +0x28, value at +0x48, forwarded gas at +0x68,
    host+0x190 at +0x70, the 20-byte executing address at +0x78, zero bytes at +0x8c and +0xa1; the other bytes are stack padding and are not compared.
    Box it (alloc 0xc8; failure -> aligned alloc error), clear host+0x149, release the old pending content (tag byte host+0x110: 0x38 none; nonzero ->
    callback through the vtable in host+0xb8; zero -> state word host+0xb8: 0 nothing, 1 an `Arc`-like state (table AB: direct call 0x4354780; table C: drop callback,
    atomic decrement, slow drop at zero, free 0xd0), otherwise the boxed request's callback and free 0xc8), then store state 2, the box pointer and tag 0. Return 4.

The two families differ only in the panic-message addresses, the empty vtable, and in table C doing step 11's replacement in the helper 0x4f00920;
the model takes the family as a parameter and both are compared against their own machine code.

## Implementation and comparison

`tools/evm_create_opcodes_115.py` contains (a) an x86-64 subset decoder and concrete evaluator that runs the handler bytes (including `lock dec`,
`mul`, `div`, `cmov`, SSE moves), (b) the pure-Python model, (c) a harness that builds host, cell, context, parameter, heap and pending-slot memory for
each case and stubs the callees by call target (allocator, memcpy, memset, free, panics, `Bytes` drops, raw reserve, pending callbacks), recording every stub call as an
event, and (d) the case generator (40 scenario modes: every status byte, limit edges for the three limit sources, exact gas edges, 2^59 word and base overflow panics,
refund counters at the signed saturation edges, zero divisor, pending slot of each kind, odd allocation pointers, allocation failures, cell shrink / full-reserve cases).
Per case the observation is: status or panic message address, remaining stack, gas, memory words and cost, cell length and borrow flag, refund counters, pending slot
words and tags, the stub event list (in order), a hash of cell memory, a hash of the heap, the defined bytes of the request box and the `Arc` counter.
Unit tests (`tests/test_evm_create_opcodes_115.py`, 15 tests, no skips) re-check statuses, limits, the 63/64 split, all pending-slot kinds, extent corruption,
digest corruption and a misaligned handler start.

Negative controls (`negative-controls.tsv`): 31 deliberately wrong model variants, 16 single-byte corruptions of the real handler / helper / expansion code (first
conditional jump inverted, first and last status-byte immediates changed) and 3 corrupted inputs (binary digest, non-function start, misaligned entry). All 50 are detected;
the file records the first detecting case for each. `equivalent-mutants.tsv` is empty (no equivalent variant was needed).

## Results and limitations

- cases: 14,000 (12,000 handler cases over both families and both opcodes + 2,000 direct memory-expansion cases), mismatches: 0 (`measure.json`, `summary.json`)
- outcome classes with counts: `outcome-classes.tsv` (e.g. CREATE queued 3,392, CREATE2 queued 3,007, initcode-too-large 977, panics 905, out-of-gas 1,484)
- negative controls: 50 total, 50 detected, 0 equivalent
- cases.tsv lists every 4th case (3,000 rows) with a digest of the full observation; the other cases are regenerated deterministically by the tool.

Limits: the concrete evaluator covers only the instruction forms these six bodies use (the decoder rejects anything else, and the instruction sweep proves full
byte coverage); callees are modelled by their contract at the call target, not by their bytes; uninitialised stack padding in the request box is deliberately not
compared; the harness memory (128 KiB cell, 128 KiB heap) bounds successful expansions - larger ones are cut off by withholding gas so the real code fails at the charge;
what the call-frame loop does with the queued request (address derivation, nonce, hash of the initcode, code deposit) is outside this packet and unresolved.

Next question: the consumer of the pending-call slot (host+0xb8 state 2) - decode the box into the child frame (address derivation, the keccak input for CREATE2).
