# RE-001: node #115 wrapped-key search with its pivot-equality shortcut

- Component: foundation; direct caller associated with `l1/src/raw_signature_tracker.rs`.
- Target: `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. Independently authored MIT research code and model; no inferred source copied.
- Bounded question: what status and logical index does `0x4551810` compute when searching sorted unsigned keys in a wrapped buffer, including duplicate keys at its wrap boundary?
- Claim status: the instruction/data relations below are observations. Ring geometry and sortedness are explicit preconditions. Original type names, symbol names and ownership are unresolved.

The function searches unsigned qword keys at the start of records with stride
`0x38`. It takes a descriptor through RDI and a needle pointer through RSI.
For the valid sorted geometry below, RAX is zero on a match and one on a miss;
RDX is a logical element index, or the insertion index on a miss. Empty input
returns `(1, 0)`. A match normally selects the last equal key within the physical
span selected for searching. The exception is a wrapped input whose first key at
physical index zero equals the needle: it immediately returns that key's logical
index, even when further equal keys follow. Thus replacing this function with a
uniform last-equal or first-equal search would change its behavior.

## Exact window and evidence denominators

All addresses are original ELF virtual addresses, and intervals are half-open.
No load bias or operand normalization is applied.

| Measurement | Value |
| --- | ---: |
| Function start | `0x4551810` |
| Function end | `0x455192b` |
| Function file offset | `0x4550810` |
| Complete body bytes | 283 |
| Strictly decoded instructions | 89 |
| Callees, including tail calls and indirect dispatch | 0 |
| INT3 bytes after body | 5 |
| Full .text bytes scanned | 83719936 |
| E8 rel32 call candidates | 15 |
| E9 rel32 tail-jump candidates | 0 |
| Total direct-call candidate sites | 15 |
| Distinct containing caller FDEs | 14 |
| Instruction-derived fixture vectors | 64 |

Body SHA-256: `aa8a369d5696b55ad505513bedea408be36ff3115ae4a044755e38bca0148c13`.
The actual FDE is at VA/file offset `0xecfbd0`,
CIE at VA/file offset `0xca6ed8`; raw records, lengths,
CIE interpretation and SHA-256 values are in `records.json`. The FDE has no LSDA.
Its exact range agrees with a complete instruction walk from the entry, internal
branch targets and terminal returns. The bytes from `0x455192b`
to the next FDE start `0x4551930` are INT3 padding, excluded
from the function body. Unwind coverage alone is not the boundary argument.
There are no code/data RIP-relative references, stack writes, memory writes,
opaque calls or external branch destinations in this body. The only RET stack
read is the normal return address; arbitrary pointer faults are outside the rule.

## Input contract and rule

The descriptor's qwords are `C=[RDI+0]`, `B=[RDI+8]`, `H=[RDI+0x10]`,
`L=[RDI+0x18]`. Interpret them as capacity, record base, raw head and length only
under these preconditions: `0<C<2^63`, `0<=H<2*C`, `0<=L<=C`, readable descriptor
and selected record keys, and no address arithmetic overflow or concurrent
mutation. The node body does not check these conditions. The model rejects
out-of-domain geometry rather than claiming the target safely rejects it.
For nonempty input the qword at RSI must also be readable. Payload bytes after
each key are neither read nor written by this function.

Set `h=H-C` if unsigned `H>=C`, otherwise `h=H`. The code subtracts capacity at
most once; it is not a general modulo routine. Under the declared head bound,
`h=H mod C`. Let `K[i]=u64(B+0x38*((h+i) mod C))` for `0<=i<L`, and require
these logical keys to be nondecreasing in unsigned order. Define
`t=min(L,C-h)`, the length of the first physical span.

- If `L=0`, return `(1,0)`. The code reads the descriptor's length and base;
  it does not dereference the needle or any record key on this route.
- If input wraps (`L>t`) and `K[t]==needle`, return `(0,t)` immediately.
- If input wraps and `K[t]<needle`, search logical indices `[t,L)`.
- Otherwise search logical indices `[0,t)`.
- Within the selected span, return `(0,j)` for its last equal key. If none
  equals the needle, return `(1,j)` where `j` is the first greater key's logical
  index, or the span end if every key is smaller. Sortedness makes this the
  insertion index in the full logical sequence.

For example, logical keys `[4,4,4,4]` at capacity four, head zero, needle four
return `(0,3)`. With head two they return `(0,2)` because the wrap pivot equals
the needle. Both examples and their head-plus-capacity forms are in the JSON
fixtures. No Rust enum or container ABI is inferred from the raw result pair.

## Instruction proof

At `0x4551810..0x4551839`, the length-zero test selects the empty path; otherwise
CMP/CMOVAE normalizes H once. SUB computes `C-h` and then `L-(C-h)`.
JBE after the latter subtraction selects the nonwrapped path on borrow or zero.
Under the input bounds these calculations cannot overflow their intended
unsigned ranges. At `0x45518b5`, adding normalized head to length and later
subtracting it restores the nonwrapped length. The empty path zeroes the index
and bypasses every key/needle load.

At `0x4551845`, unsigned CMP followed by SETA and SBB AL,0 maps the pivot
comparison to byte zero for equality, one for pivot greater, and `0xff` for
pivot smaller. SETA preserves CMP's carry. MOVZX clears the upper RAX bits.
The equality jump goes directly to RET at `0x4551916`, leaving RDX=`C-h`.
The greater route rebases RCX to `B+0x38*h` and searches the first span; the
smaller route searches the wrapped span from B and retains `C-h` as its bias.

Each binary-search loop starts with index `i=0` and length `n` of its selected
nonempty span. For `n>1`, it takes `q=floor(n/2)`, tentatively advances to
`i+q`, restores the old index only if the unsigned midpoint key is greater than
the needle (CMOVA), and sets `n=n-q`. Therefore n strictly decreases to one.
For sorted keys, the surviving interval contains the last key <= needle if one
exists; if none exists it retains the span's first key. Equality advances at
midpoints, explaining the last-equal behavior. The IMUL operands bind the key
stride, and the qword CMP operands bind key width and unsigned ordering.

The terminal CMP leaves CF set exactly when the selected key is smaller than
the needle. On inequality ADC index,0 adds that carry, converting the retained
index to the insertion position. On equality there is no increment. The
wrapped search adds its logical bias at `0x45518aa`; the other search returns
the first-span index directly. XOR/MOV plus SETNE produce a full RAX of zero
or one, not merely a partially defined AL. Callee-saved registers are untouched.
This is an all-input argument under the stated preconditions, supported by
boundary vectors; it is not a claim of captured-node execution.

### Complete strict instruction walk

The Python decoder consumes every body byte, including internal NOPs, and
rejects unsupported encodings, truncated instructions and off-boundary branches.
The raw bytes below are unmasked. JSON operands retain widths, registers,
ModRM/SIB addressing, signed displacements and branch targets.

```text
04551810  488b4718              mov rax, u64[rdi+0x18]
04551814  4885c0                test rax, rax
04551817  0f8491000000          je 0x45518ae
0455181d  488b17                mov rdx, u64[rdi]
04551820  4c8b4f10              mov r9, u64[rdi+0x10]
04551824  31c9                  xor ecx, ecx
04551826  4939d1                cmp r9, rdx
04551829  480f43ca              cmovae rcx, rdx
0455182d  4929c9                sub r9, rcx
04551830  4c29ca                sub rdx, r9
04551833  4989c0                mov r8, rax
04551836  4929d0                sub r8, rdx
04551839  767a                  jbe 0x45518b5
0455183b  488b4f08              mov rcx, u64[rdi+0x8]
0455183f  4c8b11                mov r10, u64[rcx]
04551842  488b3e                mov rdi, u64[rsi]
04551845  4939fa                cmp r10, rdi
04551848  0f97c0                seta al
0455184b  1c00                  sbb al, 0
0455184d  0fb6c0                movzx eax, al
04551850  84c0                  test al, al
04551852  0f84be000000          je 0x4551916
04551858  3dff000000            cmp eax, 0xff
0455185d  0f85b4000000          jne 0x4551917
04551863  31f6                  xor esi, esi
04551865  4983f801              cmp r8, 1
04551869  742e                  je 0x4551899
0455186b  0f1f440000            nop u32[rax+rax*1]
04551870  4889f0                mov rax, rsi
04551873  4d89c1                mov r9, r8
04551876  49d1e9                shr r9, 1
04551879  4c01ce                add rsi, r9
0455187c  4c6bd638              imul r10, rsi, 0x38
04551880  4a393c11              cmp u64[rcx+r10*1], rdi
04551884  480f47f0              cmova rsi, rax
04551888  4d29c8                sub r8, r9
0455188b  4983f801              cmp r8, 1
0455188f  77df                  ja 0x4551870
04551891  486bc638              imul rax, rsi, 0x38
04551895  4c8b1401              mov r10, u64[rcx+rax*1]
04551899  4939fa                cmp r10, rdi
0455189c  7404                  je 0x45518a2
0455189e  4883d600              adc rsi, 0
045518a2  31c0                  xor eax, eax
045518a4  4939fa                cmp r10, rdi
045518a7  0f95c0                setne al
045518aa  4801f2                add rdx, rsi
045518ad  c3                    ret
045518ae  31d2                  xor edx, edx
045518b0  4531c9                xor r9d, r9d
045518b3  eb06                  jmp 0x45518bb
045518b5  4c01c8                add rax, r9
045518b8  4889c2                mov rdx, rax
045518bb  496bc938              imul rcx, r9, 0x38
045518bf  48034f08              add rcx, u64[rdi+0x8]
045518c3  4c29ca                sub rdx, r9
045518c6  b801000000            mov eax, 1
045518cb  4885d2                test rdx, rdx
045518ce  7458                  je 0x4551928
045518d0  488b36                mov rsi, u64[rsi]
045518d3  31ff                  xor edi, edi
045518d5  4883fa01              cmp rdx, 1
045518d9  7426                  je 0x4551901
045518db  0f1f440000            nop u32[rax+rax*1]
045518e0  4989f8                mov r8, rdi
045518e3  4989d1                mov r9, rdx
045518e6  49d1e9                shr r9, 1
045518e9  4c01cf                add rdi, r9
045518ec  4c6bd738              imul r10, rdi, 0x38
045518f0  4a393411              cmp u64[rcx+r10*1], rsi
045518f4  490f47f8              cmova rdi, r8
045518f8  4c29ca                sub rdx, r9
045518fb  4883fa01              cmp rdx, 1
045518ff  77df                  ja 0x45518e0
04551901  486bd738              imul rdx, rdi, 0x38
04551905  48393411              cmp u64[rcx+rdx*1], rsi
04551909  7504                  jne 0x455190f
0455190b  31c0                  xor eax, eax
0455190d  eb04                  jmp 0x4551913
0455190f  4883d700              adc rdi, 0
04551913  4889fa                mov rdx, rdi
04551916  c3                    ret
04551917  496bc138              imul rax, r9, 0x38
0455191b  4801c1                add rcx, rax
0455191e  b801000000            mov eax, 1
04551923  4885d2                test rdx, rdx
04551926  75a8                  jne 0x45518d0
04551928  31d2                  xor edx, edx
0455192a  c3                    ret
```

## Caller census and first-party association

The producer scans every byte in `.text [0x1419300,0x63f0a00)` for
E8/E9 with a signed rel32 destination equal to this entry, including the final
possible instruction position. It retains every match, containing actual FDE,
caller body hash, decoded call and following result test. Counts refer to
byte-scan candidates: the scan is not a global instruction-boundary proof, and
cannot discover register calls, relocated function pointers, other executable
sections or jumps into the middle of the body. Exploratory full-FDE GNU
objdump decoding confirmed the listed call starts; reproduction and tests use
only Python and the authenticated image, with no objdump dependency. Caller
control flow and result handling beyond the following tests remain unbound.

| Call site | Containing FDE interval | Following result test |
| --- | --- | --- |
| `0x368afc0` | `0x368acd0..0x368b9c4` | `test al, 1` |
| `0x368bc3d` | `0x368b9d0..0x368c5ab` | `test al, 1` |
| `0x368c86d` | `0x368c5b0..0x368d379` | `test al, 1` |
| `0x368d830` | `0x368d380..0x368e2dd` | `test al, 1` |
| `0x368e55d` | `0x368e2e0..0x368eeac` | `test al, 1` |
| `0x36c7bde` | `0x36c7b30..0x36c7f6d` | `test al, 1` |
| `0x36c8032` | `0x36c7f70..0x36c8424` | `test al, 1` |
| `0x36c84ed` | `0x36c8430..0x36c8776` | `test al, 1` |
| `0x36c95ae` | `0x36c93c0..0x36ca5a8` | `test al, 1` |
| `0x36c9fbe` | `0x36c93c0..0x36ca5a8` | `test al, 1` |
| `0x36ca66f` | `0x36ca5b0..0x36ca93b` | `test al, 1` |
| `0x36ca9eb` | `0x36ca940..0x36cab86` | `test al, 1` |
| `0x371426b` | `0x37141b0..0x371438a` | `test al, 1` |
| `0x3cdae9a` | `0x3cdad90..0x3cdb29e` | `test rax, rax` |
| `0x44829da` | `0x4482950..0x44830f3` | `test al, 1` |

Caller `0x368acd0` contains a decoded LEA at
`0x368b335` of Location `0x6468b38`. Its actual R_X86_64_RELATIVE
relocation resolves the filename pointer to `l1/src/raw_signature_tracker.rs`; the length,
line `231` and column `9` are checked from bytes.
The same FDE contains the direct call at `0x368afc0`. This is a
first-party caller association, not proof that the leaf originated in that
file, that its key is a particular signature field, or that its source container
was a particular Rust standard-library or private type. No callee identities or
extents are omitted: the fully decoded leaf has no callees.

## Novelty and scope selection

Before implementing this packet, at the recorded source base, these exact
commands each returned exit code one with empty stdout and stderr:

```sh
rg -i 4551810 research/
rg 72685584 research/
rg -i 4551810 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg 72685584 ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'wrapped-key56-search|wrapped_key56_search' ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The packet directory and tool/test names did not exist. This is a historical
pre-addition check; a current search naturally finds this packet. The chosen
entry lies within the assigned band. No additional function's behavior is bound,
so no callee novelty exception is needed. This work addresses RE-001's concrete
unknown search result and duplicate selection; it requests no catalogue,
progress, component or full-function-map gate change.

## Reproduce and validation

From repository root, materialized authenticated target required. The observed
local interpreter was Python 3.13.5 on Linux x86-64; the code requires Python
3.10+ and standard-library modules only. Exploratory disassembly used GNU
objdump 2.44; it is not invoked or parsed by the producer, verifier or tests.

```sh
python3 tools/node115_wrapped_key56_search.py --out research/work-items/RE-001-node115-wrapped-key56-search/
python3 -m unittest tests.test_node115_wrapped_key56_search -v
python3 research/work-items/RE-001-node115-wrapped-key56-search/verify.py
make verify
make catalogue-check
```

`records.json` contains semantic evidence, instruction operands, caller/data
bindings and instruction-derived vectors. `README.md` is rendered from those
records. The generator does not read the retained records as its oracle.
`MANIFEST.sha256` covers the exact whitelisted packet files, producer, tests
and existing ELF/FDE parser dependencies. The verifier rejects missing, extra,
duplicate or changed entries and regenerates all produced evidence into a
temporary directory for byte comparison. It does not execute captured code.

Targeted controls include wrong image digest, mutations throughout the complete
window, shifted FDE range, changed padding, redirected caller target, Location
reference/relocation/path corruption, malformed decoder inputs and a semantic
CMOVA-to-CMOVAE counterexample at an actual midpoint. Public generation rejects
bad identity before creating output; internal structural checks are separately
attacked below that gate with copy-on-write mappings. The independent bisect
model is compared with the decoded narrowing relation across sorted geometry,
wrap boundaries, duplicate pivots and unsigned extremes. Tests check the README
measurement table against JSON and require exact regenerated README equality.

## Non-claims, limitations and next step

This closes a bounded static leaf rule, not an integrated implementation.
Rust reconstruction, compiler flags, Cargo closure, two-build comparison,
normalized or raw compiled-code identity, runtime differential tests and hosted
CI are not implemented/measured here. No node/visor was executed; no public
network, chain action, install, signing, private state or upstream write was used.
There are no normalization masks. Helper closure is local and complete because
there are no calls; indirect incoming references, caller semantics, object/type
layout provenance and whole-ELF equivalence remain open. Invalid geometry,
unsorted keys, invalid memory and concurrent mutation are outside the theorem.

Before this packet, the retained research did not bind this entry. After it,
the full body, its search and duplicate-index rule, and its source-associated
caller edge can be reproduced against the pinned target. All full-scope
acceptance gates remain unchanged. The next question is which caller writes
and sortedness invariants establish this descriptor's key meaning, especially
whether duplicate keys can reach the pivot-equality shortcut in normal use.
