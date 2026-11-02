# RE-001: checked capped advance at 0x3b9d9b0 (node #94)

Task: RE-001; component: l1-shared. Bounded question: how does this
function update the first object qword and produce its return value from the
input offset and the second object qword, including overflow and cap boundaries?

Answer: let `old=qword[rdi+0]`, `extra=qword[rdi+8]`,
and `offset=rsi`, all unsigned 64-bit values. Compute `t=old+offset`,
`q=t+1`, then `z=q+extra`, checking overflow at each stage. Before any object
store, an overflow transfers to the fixed-slot callee identified below with
the source Location in RDI; the callee's behavior is outside this bind. If
`z<=30`, store `q` to the first qword and return `RAX=t`. Otherwise,
store 30 and return `RAX=(q & ~0xff)|30`: only AL is overwritten
on this path. The second qword is read only. This is a complete decode of the
function's own instructions, with a deliberately explicit callee boundary.

## Identity and scope

Target: `artifacts/node/94/hl-node`, 91774280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. All addresses are ELF VAs, with no analysis rebase.
Baseline repository commit: `e5c9b6436876b2a4a39daef813171f9879317699`. No inferred reference
source was used or copied; the rule and model were authored from binary bytes.
Source-build flags, dependency closure and compiled comparison are unmeasured.

| Function field | Observed value |
| --- | --- |
| Interval (exclusive end) | `0x3b9d9b0..0x3b9d9f7` |
| Body bytes | 71 |
| File offset | `0x3b9c9b0` |
| Body SHA-256 | `1b77785b7ec902c12d4792412e3e3d0302844e66d94a947905be97b539ae3d64` |
| FDE section offset / length field | `0x1b9f64` / 28 |
| CIE section offset | `0x0` |
| Following FDE | `0x3b9da00` at `.eh_frame+0x1b9f84` |
| Inter-FDE padding bytes | 9 (`cc`, outside function) |

The actual `.eh_frame` records, including CIE association, determine the
extent. The verifier rejects overlapping FDEs and shifted boundaries. The
instruction decode corroborates the successful return paths and the final
outgoing call. It does not infer a nonreturn guarantee from the FDE end.

## Instruction walk and source evidence

[`instructions.txt`](instructions.txt) contains the bytes and the strict
decoder's instruction walk: 23 instructions,
4 conditional branches and 2
return sites. `push rax` reserves stack space; successful paths balance it
with `pop rcx`. `add rsi,[rdi]` checks carry; `inc rax` checks zero after
increment; `add rcx,rax` checks carry again. All failure edges converge at
the Location load. The unsigned `jbe` accepts equality at the cap. On that
path `q+extra<=cap` implies `t<cap`, proving the final `cmovb` selects `t`.
On the capped path `mov al,cap` preserves upper RAX bits. The model and
vectors retain this distinction instead of assuming an integer-wide return.
The return type itself remains unknown.

The relocated Location at `0x5712ff0` points to the binary's first-party
build-root path ending in `l1/src/system_user.rs:3:23`.
Its full path is 50 bytes, SHA-256 `5035127abbb1264ef3c651e542cb4e9a8a4e05e0e12dc1ca27a3bca634276921`;
the captured build prefix is checked but omitted from prose. The file pointer
is zero on disk and resolved by `R_X86_64_RELATIVE`; the parser checks the
relocation, path bytes, length, line and column. This supports a first-party
system-user connection, not a source-level function name or iterator type.

## Callee and incoming references

Outgoing callee count: 1. The instruction at
`0x3b9d9f1` is `ff15` through RIP-relative slot
`0x576e118`. Its on-disk slot is zero; a checked
`R_X86_64_RELATIVE` relocation resolves it to `0x157b480`.
This is a statically fixed slot, not demonstrated polymorphic dispatch.

| Callee field (identity only) | Observed value |
| --- | --- |
| Interval / bytes | `0x157b480..0x157b499` / 25 |
| Body SHA-256 | `1942fe4d3c3a14b88f1cc4ad4a627f2c97b5bd6983d5ba6a77dfd50fb8e395e6` |
| FDE offset / length field / CIE | `0x199b4` / 24 / `0x0` |
| Padding bytes / next FDE | 7 / `0x157b4a0` |

The shared callee has existing research mentions. Only its digest, extent,
CIE, padding and slot identity are checked here; no behavior or transitive
callee is rebound. In particular, the packet does not claim that the call
returns, unwinds or aborts. If it returns normally, the next address lies in
the recorded `int3` padding. No object store precedes this call, although the
function has pushed a stack word.

A full `.text` e8/e9 rel32 scan examines 70370352 bytes starting
at `0x1343c80`: 0 e8 candidates and
0 e9 candidates target this exact entry. It is a
byte-position scan, not a general instruction-boundary proof. It does not
cover indirect calls, interior-entry targets, other sections or all data
xrefs. A separate full RELA scan finds 1 pointer slot,
`0x5776280`, relocating to the function. Its use is unknown;
absence of direct calls does not establish that this function is unused.

## Novelty checked before implementation

Against the baseline above, these research commands returned empty output
(rg status 1), with 0 matches:

```sh
rg -i '3b9d9b0' research/
rg -i '62511536' research/
```

The following command also returned empty output (rg status 1), with
0 matches. `PR_LIST_DIR` denotes the supplied
snapshot directory; its machine-local absolute path is intentionally omitted.

```sh
rg -i '3b9d9b0|62511536' "$PR_LIST_DIR/open_prs.txt" "$PR_LIST_DIR/merged_prs.txt" "$PR_LIST_DIR/closed_unmerged_prs.txt"
```

| Snapshot | Bytes | SHA-256 |
| --- | ---: | --- |
| open_prs.txt | 56488 | `c254c57d541b199fd589cb386324a579eba28a74cabff3309aaa9e2971c4066c` |
| merged_prs.txt | 110952 | `c291aef81f04946a0e6594630e2a5538052c57d12bc79580150555ee0d89ac6d` |
| closed_unmerged_prs.txt | 15108 | `7ffc9b73e46cf197874fe3cc691a8c8380e5ef8139dc4d23d90ff7db86819406` |

These are historical pre-addition checks; repeating them on this branch will
find this packet. No callee behavior is in the novelty claim. Neighbors and
shared-callee mentions are not claimed as new work.

## Reproduction and checks

Python 3.10+ standard library only. No target execution, network access,
external disassembler or installed package is required. The reproducer maps
the binary read-only, authenticates its entire digest, parses ELF/FDE/RELA,
strictly decodes the function, scans `.text`, and emits byte-identical evidence.
`records.json` contains semantic records, not an instruction inventory.
`verify.py` enforces an exact manifest whitelist, hashes the evidence and
checker/test sources, and regenerates the evidence from the authenticated
input for equality. The verifier shares the reproducer's parser and decoder;
it is not an independently implemented disassembler.
No normalization or byte substitution is used.

```sh
python3 tools/system_user_capped_advance.py --out research/work-items/RE-001-system-user-capped-advance-94/
python3 -m unittest tests.test_system_user_capped_advance -v
python3 research/work-items/RE-001-system-user-capped-advance-94/verify.py
make verify
make catalogue-check
```

The model uses 3 checked arithmetic stages and
14 manually worked instruction-derived vectors. Tests cover
the cap equality, the low-byte-only write, each overflow transfer before an
object store, and a separate interpreter of decoded instructions. Corruption
controls reach the structural checker with the digest gate deliberately
separated: body mutation, shifted FDE, CIE association, callee relocation,
Location relocation, padding and callee body. Public entrypoints always
authenticate the target and have no digest-bypass option. README equality
with its JSON-derived rendering is tested. Manifest traversal, duplicate,
missing and extra entries are rejected. These are static checks and model
comparisons; they are not differential execution of the target.

The initial repository `make verify` stopped at the unrelated node #115 LFS
pointer. The final repository-check outcomes are reported in the local result
and PR draft; no repository-wide success is implied by this packet's verifier.

## Non-claims, limitations and next step

- No captured execution, Rust implementation, compiled comparison or whole-node equivalence.
- No source-level function/type name, iterator trait, system-user policy or field ownership recovered.
- No shared-callee behavior, nonreturn guarantee, transitive call closure or runtime relocation execution.
- No #115/visor transfer, catalogue/progress change or full-scope acceptance gate.

The model assumes valid readable/writable object memory, a valid disjoint
stack and no concurrent mutation. It does not model memory faults. The callee's effects and
nonreturn status remain open; the function's ABI type and pointer-slot use are
also unresolved. Next, trace the relocating pointer slot to its consumer to
establish the return-width contract and the meanings of the object fields.
All full-scope gates remain unchanged.
