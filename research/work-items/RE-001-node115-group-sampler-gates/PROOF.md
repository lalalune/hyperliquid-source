# Native contract and proof boundaries

Addresses are ELF VAs; ends are exclusive. File offsets, hashes and FDE/CIE bindings are in `records.json`. Objdump's nearby dynamic-symbol labels are not recovered Rust names.

## Entry and ordering

The complete FDE is `0x5b298d0..0x5b2a121`. The LEA at `0x5b299d7` supplies Location `0x64bca88`, whose RELATIVE relocation points to the 33-byte path `node/src/group_and_seq_sampler.rs` at `0x431e32`. Its tail is `(length=33,line=169,column=10)`.

Entry RDI is saved as state pointer RBX, RSI as input key R14, and RDX as timestamp-carrier pointer R15. Calls to `0x5c842e0` with EDI=1 and `0x5c84210` precede a local floating conversion. A second call to `0x5c842e0` overwrites the timestamp carrier's qword `+0` and dword `+8`. The body then calls `0x4dca370` with the state and incoming key, followed by `0x4da5d60` with the saved key and a zero byte. Its returned RAX becomes RDI for `0x64e1010 -> 0x1547530`, with ESI=1, the source Location and the computed XMM0 value.

Those calls and stores occur **before** the outer collection gate. The float conversion and helper internals are exported context, not recovered here. In particular this packet does not prove time units, exact rounding, epoch, or clock monotonicity.

At `0x5b299fd`, slot `0x64e0990 -> 0x1629690` receives a pointer to a 12-byte stack carrier at `rsp+0x12c`. The gate call at `0x5b29a0a` uses `(RDI=state+0x20, RSI=&carrier)` through `0x64e0008 -> 0x154ce40`. `test al,al; je` returns directly when its low byte is zero. All other byte values enter grouping. No claim is made about the helper's policy, mutation or timing threshold.

## Flat record scan

The body reads four state qwords: offsets 0, 8, 16, 24. For the selected non-sentinel representation, infer these as `(capacity,data,head,length)`. `neg`/`jno` distinguishes the alternate `0x8000000000000000` representation; alternate iterator behavior is outside the flat-span proof.

Premises: accessible valid storage; nonzero capacity below 2^63; `0 <= head < 2*capacity`; `0 <= length <= capacity`; all address and length products representable; non-aliasing valid output containers. These are admitted-container premises, not runtime validation performed by this function. Empty length makes both spans empty. For nonempty length, normalize `h = head - (capacity if head >= capacity else 0)` once, and let `space=capacity-h`:

- `length <= space`: spans `[h,h+length)` and `[0,0)`.
- `length > space`: spans `[h,capacity)` and `[0,length-space)`.

`0x5b29a62..0x5b29ac0` implements this split and scales all endpoints by **0x268 = 616**. The iterator at `0x5b29b20..0x5b29b70` exhausts the first span, replaces it with the second, and advances the yielded record pointer by 616. The modulo-index reference independently checks that concatenating both spans gives `(head+i) mod capacity` for every `i` in the admitted length. Other representations call `0x5140660`; their yielded pointers are only a premise for the common record-load path.

## Group lookup request and pair append

On a flat record at P, R12 is P+8. The common path uses:

| Instruction | Native value | Flat record offset |
| --- | --- | --- |
| `0x5b29b82` | RBP = qword at yielded RAX | `+0` |
| `0x5b29b85` | EDX = dword at R12+0x240 | `+0x248` |
| `0x5b29ba3` | R15 = qword at R12+0x200 | `+0x208` |

EDX goes to `0x4dc46c0` with a temporary collection rooted at `rsp+0x50`; `0x4da50b0` returns a pointer R13 to a three-qword vector-like carrier. This binds the group-key request, not the helper's key equality or deduplication policy. The temporary is initialized as `(0,8,0,0)` before iteration.

Given a valid returned `(capacity,pointer,length)` carrier, the body compares length with capacity, calls reserve slot `0x64ebf80 -> 0x5962620` on equality, and reloads the data pointer. It writes `R15` at `data+16*length` and `RBP` eight bytes later, then increments and stores length. Thus the pair order is **(field +0x208, original key)**. No reserve-success, capacity-overflow, alias, allocation-error or malformed-header behavior is inferred beyond these requests. Source names motivate the local label 'sequence'; the economic meaning of either qword remains unknown.

## Two collection gates

The temporary's qword at `rsp+0x68` serves as a group-count-like value G. At `0x5b29bd6`, unsigned `cmp G,3; jb` skips the first request for G<3. Otherwise, the body builds a cursor, calls `0x5b70cf0` at **`0x5b29cba`**, and conditionally requests release of the returned buffer with byte size `8*returned_capacity` and EDX=0. It then reloads G.

At `0x5b29cdf`, unsigned `cmp G,1; jbe` skips the second request for G<=1. Otherwise ECX loads the provider carrier's dword at `rsp+0x130` (carrier+4), a separate value from the earlier elapsed-sample temporary. Let that raw u32 be x. The straight-line span computes:

```
H = (x * 0x91a2b3c5) >> 43
M = (x * 0x88888889) >> 37
R = (M * 0x08888889) >> 33
Y = M - 60*R + 60*H
```

The products are native 64-bit operations; the scaled terms, subtraction and final addition use 32-bit values. The gate compares Y unsigned against 6 and skips on `<6`. If admitted it builds another cursor and calls the **same helper** at **`0x5b29e02`**, followed by the same conditional release pattern. The two branches are independent in program order, not `if/else` alternatives. Counts are loaded separately: the report's equal-count examples assume the first helper leaves the local group count unchanged. `relations.py` also checks independent first and second counts.

### Exact reciprocal proof

For `x=d*q+r`, `0<=r<d`, choose integer multiplier A and shift s. Let `e=d*A-2^s`. Then

```
x*A/2^s = q + (q*e + r*A)/2^s.
```

For each native reciprocal, e is nonnegative and the conservative residual upper bound is strictly below 2^s:

| d | A | s | maximum input | e | residual upper bound | 2^s |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 3600 | 2443359173 | 43 | 4294967295 | 592 | 8794355946859 | 8796093022208 |
| 60 | 2290649225 | 37 | 4294967295 | 28 | 137152622339 | 137438953472 |
| 60 | 143165577 | 33 | 71582788 | 28 | 8480174331 | 8589934592 |

Consequently H=floor(x/3600), M=floor(x/60), R=floor(M/60). The integer identity floor(floor(x/60)/60)=floor(x/3600) cancels the two scaled terms, so **Y=floor(x/60)**. Products fit u64, the scaled terms fit u32, M−60R is in 0..59, and the final sum fits u32; no wrap invalidates the algebra. Hence the second numerical gate is exactly **x>=360** over the full u32 domain. No interpretation as seconds, elapsed duration or time-of-day is needed for this result.

Assuming the outer gate admits and the count is unchanged:

| G | x<360 | x>=360 |
| ---: | --- | --- |
| 0 or 1 | neither call | neither call |
| 2 | neither call | second call |
| 3 or more | first call | both calls |

## Limits and falsification

The packet authenticates 18 encoded incoming E8 calls, all within caller FDE `0x54a9c70..0x54b66a2`, by decoding that complete owner. It does not reconstruct that caller or prove invocation at runtime. No RELATIVE slot targets the selected entry; arbitrary register/vtable/dynamic dispatch is not ruled out. A second specialization at `0x5b2a130` is an unclaimed lead.

The full native export includes all 28 calls and cleanup. Relevant relocations are checked independently; direct calls are resolved in the report. Helper bodies, record semantics in the alternate representation, duration conversion constants, concrete collection contents, logging, allocation failures and unwind call-site coverage remain unclosed. The tail contains cleanup but no LSDA semantic claim is made. The evidence establishes local requests under normal helper returns, not whole-sampler equivalence or an output log.

There are 27 deep corruptions: 18 instruction spans, six RELATIVE bindings, two source/Location spans, one FDE range. Each must fail after image/body/export checks are bypassed. Eight actual-byte counterfactuals change both a local prediction and an authenticated obligation: both count thresholds, all three reciprocals, the normalized threshold, the sequence-source displacement and the flat iterator advance. The last changes only the advance instruction; no claim is made that other endpoint multipliers change with it. Mathematical boundary checks are independent from the full-body byte comparator, and no target instruction is executed or emulated.
