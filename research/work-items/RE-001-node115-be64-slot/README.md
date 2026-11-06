# RE-001: eight-byte big-endian value into a 32-byte slot

- Component: RE-001 function map; ownership and original name unknown.
- Target: Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reference revision: none.
- Bounded question: what does the complete function at `0x29962e0` do with its input cursor and slot array?

For valid, non-overlapping input/object/destination memory, when the unsigned
qword at `rdi+0x30` is at most 1023, the function increments it, reads eight
bytes from the pointer at `rdi+0x118`, interprets those bytes as a big-endian
u64, stores that number in little-endian form at the start of the 32-byte slot
indexed by the original count, clears the slot's remaining 24 bytes, advances
the input pointer by eight modulo 2^64, and returns zero in RAX. Otherwise it
leaves memory untouched and sets AL to 45; the upper 56 bits of RAX retain the
original count. No source-length or destination-capacity check is performed here.

## Observations and extent

ELF virtual range `0x29962e0..0x299632f`, 79 bytes, file offset
`0x29952e0`, SHA-256 `6e5593a8eeb8faebb0295bff12057a7bba867f9cf5e1b7311356d42a9001ba05`. The `.eh_frame` FDE at
`0xd73c58` references CIE `0xca6ed8` (`zR`, no LSDA), and describes exactly
this range. The following byte is `cc`, before the next FDE at
`0x2996330`. FDE bounds alone do not prove function bounds;
the decoded entry, internal branch, and both returns support this local extent.
The body has 20 instructions, 0 callees and no indirect transfers.
Raw bytes, FDE and CIE records are in `records.json`; no normalization masks are used.

## Complete instruction walk

- `0x29962e0` `488b4730` mov rax, qword [rdi+0x30]
- `0x29962e4` `483dff030000` cmp rax, 0x3ff
- `0x29962ea` `7740` ja 0x299632c
- `0x29962ec` `488b8f18010000` mov rcx, qword [rdi+0x118]
- `0x29962f3` `488d5001` lea rdx, [rax+1]
- `0x29962f7` `488b7728` mov rsi, qword [rdi+0x28]
- `0x29962fb` `48895730` mov qword [rdi+0x30], rdx
- `0x29962ff` `488b11` mov rdx, qword [rcx]
- `0x2996302` `480fca` bswap rdx
- `0x2996305` `48c1e005` shl rax, 5
- `0x2996309` `48891406` mov qword [rsi+rax], rdx
- `0x299630d` `0f57c0` xorps xmm0, xmm0
- `0x2996310` `0f11440608` movups [rsi+rax+8], xmm0
- `0x2996315` `48c744061800000000` mov qword [rsi+rax+0x18], 0
- `0x299631e` `4883c108` add rcx, 8
- `0x2996322` `48898f18010000` mov qword [rdi+0x118], rcx
- `0x2996329` `31c0` xor eax, eax
- `0x299632b` `c3` ret
- `0x299632c` `b02d` mov al, 0x2d
- `0x299632e` `c3` ret

The unsigned `ja` skips all writes. On the success route the count store
precedes the source load, and the cursor store follows all slot stores. These
ordering details matter if memory aliases or faults: the rule above assumes
valid non-overlapping memory and makes no atomicity claim. `bswap` reverses the
loaded bytes on little-endian x86-64; it does not establish a protocol type.

## Callers and scope

A byte-wise scan of the entire `.text` range `0x1419300..0x63f0a00`
for `e8` and `e9` followed by signed rel32 found 0 candidates
targeting this entry. This is not a complete caller census: indirect calls,
relocations, and code outside `.text` are not resolved; byte candidates, if any,
may start within another instruction. No caller identity or first-party ownership
is claimed. No callee behavior is bound because the body calls none.

## Novelty check

Before selection, the combined hex and decimal search produced no matches (ripgrep exit 1):

```sh
rg -i '29962e0|43606752' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

## Reproduction and controls

From the repository root, with Python 3.10+ and the authenticated artifact:

```sh
python3 tools/node115_be64_slot.py --out research/work-items/RE-001-node115-be64-slot/
python3 -m unittest tests.test_node115_be64_slot -v
python3 research/work-items/RE-001-node115-be64-slot/verify.py
```

The stdlib-only producer hashes the input before parsing; it decodes only the
listed exact instruction forms and rejects any other encoding. It regenerates
this README, `records.json` and the manifest. The focused tests exercise count
boundaries, byte order, pointer wrap, altered instructions/branch, FDE shift,
wrong digest, truncation and README count consistency. Static analysis only; no
captured executable or network is used. Tool observation was complete within
the stated window and scan range. Analysis environment: Linux x86-64, Python
3.13.5; no native disassembler is needed for regeneration.

## Inference, non-claims and next step

The big-endian value and slot are raw layout observations, not recovered Rust
types, application meaning, source identity, or wire format. Runtime pointer
validity, faults, aliasing, indirect callers and source bounds remain unknown.
There is no reconstructed Rust implementation, build, raw or normalized binary
comparison, relocation closure, whole-node equivalence, or component gate claim.
Before this packet the address had no binding in the checked research and PR
lists; after it the local normal-return rule is byte-backed. Next, locate an
indirect reference or containing dispatch table to establish the caller and the
meaning and bounds of the eight input bytes.
