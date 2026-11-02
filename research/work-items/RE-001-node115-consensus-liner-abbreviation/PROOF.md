# Native relations and limits

All addresses are ELF virtual addresses; ends are exclusive. `records.json` supplies file offsets and whole-body hashes. Readelf and the repository ELF parser agree on FDE boundaries. Assembly labels emitted by objdump relative to a distant dynamic symbol are not function names.

## Source and input

The two RIP-relative LEAs at `0x4ec8135` and `0x4ec80c7` supply `0x649dcc8` and `0x649dce0` to the failure route. Each RELATIVE relocation points to `0x43bead`, exactly 27 bytes spelling `node/src/consensus/liner.rs`. Their following fields are `(length=27,line=269,column=33)` and `(27,269,50)`. This is source-location evidence for the body, not recovery of its Rust function name.

Entry RDI is the output carrier; entry RSI is saved in R14. Input offsets `+0`, `+8`, `+16` serve respectively as capacity/release-size, data pointer, and byte length. These inferred owned-string roles follow the later release and slice requests; exact Rust type/layout stability across releases is not claimed. The memory and ownership premises are a valid UTF-8 input carrier, accessible input data, writable output, valid aliasing for the original Rust call, and normal helper returns where stated. Arbitrary forged carriers are outside scope.

`0x4ec7ffc..0x4ec8011` reads length, compares unsigned against 21, then compares the first word to little-endian `0x7830` (`0x`). The length gate precedes that data read. Under 21, or a different prefix, goes to `0x4ec8011`: copy the final qword and first 16 bytes to output, return the output pointer in RAX. No allocation/format/release helper is called on this route. The input header is not cleared: this is an ownership transfer under the original call's ownership rules, not a safe clone of two independent owners.

## Prefix and suffix

At `0x4ec802d`, ECX begins at 6. The body tests bytes 6, 5, 4, 3, 2 in descending order. Each `cmp byte,0xbf; jg` is **signed**: `i8(byte) > -65`. For all 256 byte values this is exactly `byte & 0xc0 != 0x80`, the non-continuation predicate. The final raw fallback computes 0 or 1 from byte 1. For valid UTF-8 with the admitted prefix, this fallback is unnecessary: byte 2 is a boundary, and the maximum encoded scalar width is four, so a boundary exists in 3..6. The selected index is therefore the greatest boundary at or below 6, not six characters.

At `0x4ec806d`, the suffix tests positions `n-4`, `n-3`, `n-2`. Signed `jle` skips a continuation byte. The last candidate is `n-1`; `cmovl` against signed -64 substitutes `n` if that byte is a continuation. For valid UTF-8 a boundary exists in the last four bytes, so the result is the least boundary at or above `n-4`, retaining 1..4 bytes. A malformed raw byte sequence could hit the empty-tail fallback; this is not an accepted-input or validation claim for malformed UTF-8.

The prefix check at `0x4ec80a1..0x4ec80b0` admits zero or a non-continuation boundary. The suffix check subtracts the selected start from n; `jbe` followed by `jne` distinguishes exact end from unsigned underflow, then checks a nonempty suffix's boundary. With the valid-input premise these checks succeed. Their failing routes converge on slot `0x64df670 -> 0x16806c0`, with separate source Locations, then UD2. The failure helper's message, panic policy and argument meanings beyond the observed registers remain unresolved.

The predicate truth table plus UTF-8's maximum width proves the relation for all valid inputs; the finite composition and endpoint checks are supporting falsification cases, not an exhaustive enumeration of strings. NUL and non-hex characters have no extra gate here.

## Formatter request and ownership

The native stack records are:

| Offset | Value |
| --- | --- |
| `rsp+0` | original data pointer |
| `rsp+8` | prefix byte length |
| `rsp+16` | data pointer + suffix start |
| `rsp+24` | n − suffix start |
| `rsp+32` | pointer to prefix pair |
| `rsp+40` | callback `0x5616320` |
| `rsp+48` | pointer to suffix pair |
| `rsp+56` | same callback |

`0x4ec8114` calls slot `0x64df6e8 -> 0x141e3a0` with RDI=output, RSI=`0x435d5c`, RDX=`rsp+32`. Exactly six descriptor bytes are authenticated: `c0 02 2e 2e c0 00`. The adjacent descriptor is excluded. Two arguments and the literal dots support the abbreviation label, but this packet does not infer a complete format grammar from those bytes.

The callback's entire FDE is `0x5616320..0x5616333`. It preserves incoming RSI as the first outgoing argument, loads outgoing RSI and RDX from the argument pair at incoming RDI, and tail-jumps via `0x64df720 -> 0x167fa70`. Thus both selected slices are forwarded with their explicit byte lengths. The shared callback is supporting context, not a claim to newly reconstruct generic Rust formatting.

After a normal formatter return, `0x4ec811a` loads input offset 0. Nonzero invokes slot `0x64df4a0 -> 0x635de30` with `(RDI=data,RSI=capacity,EDX=0)`; zero skips it. RAX is restored to the output carrier pointer. The allocator's implementation and exact meaning of EDX are not recovered; 'release request' is an inferred role, not proof of deallocation internals.

`0x4ec8149..0x4ec8167` is a cleanup tail that preserves RAX, makes the same capacity-gated request, then calls `0x63f0a50` (objdump names the PLT entry `_Unwind_Resume`). It is exported and byte-bound. This packet does **not** decode LSDA call-site tables, so it does not claim which throws or calls enter this tail. It does not establish panic safety or exactly-once destruction across unwinding.

## Callers, mutation checks and unresolved work

Two encoded E8 calls reach the primary entry: `0x4ec7d2b` and `0x543d8e8`. Each candidate is qualified at an instruction boundary after decoding its complete owning FDE. No RELATIVE relocation targets the primary entry, hence no FF15/FF25 call through such a slot is present. Arbitrary register, vtable, tail or computed calls are not ruled out. Caller arguments and log-message reachability remain unclosed.

Thirteen instruction obligations, six RELATIVE targets, four literal/Location spans and two FDE ranges yield 25 deep corruptions. Seven further counterfactuals alter actual length, prefix, byte-budget, signed branch or capacity-gate bytes. Each changes a concrete static prediction and is rejected by an obligation without relying on a whole-file hash. In the suffix-budget counterfactual only the LEA displacement changes; the comparison still reads `n-4`. Likewise the prefix-index counterfactual changes ECX while the first comparison still reads byte 6. The chosen ASCII witnesses deliberately satisfy those unchanged comparisons.

No function bytes were transplanted into an implementation, executed, or emulated. Python computes independently stated branch relations only. Full formatter behavior, allocation failures, LSDA/unwind coverage, invalid-input behavior and a compiled Rust reconstruction are explicitly not measured. The contribution resolves the source-bound admission and slice/request contract, leaving those larger contracts for later evidence.
