# RE-001: node94 TLS state threshold, circular membership and cached fields

- Component: `foundation`; one bounded helper-closure question: how does the TLS state setter cross numeric threshold 2, update the global circular structure, and refresh the two cached fields?
- Target: node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Reference source: none used or copied. Numeric state meanings and exact allocator source/version remain unknown.
- Included: three complete FDEs: setter `[0x555a4c0,0x555a688)` (456 bytes), membership insertion `[0x555a290,0x555a36d)` (221 bytes), and field refresher `[0x5559a90,0x5559af1)` (97 bytes): **774 bytes / 3 FDEs**. Two PLT stubs are symbol-identification anchors, excluded from the claimed helper-byte denominator.
- Excluded: callers' complete behavior, all incoming references, mutex fallback body, other allocator helpers, concurrency correctness, Rust reconstruction and target behavioral execution. No progress gate requested; all component gates stay false.

## Gap and overlap

The previous `RE-001-tls-table-slowpath-94` packet / PR #1916 explicitly leaves `0x555a4c0` and `0x5559a90` unresolved. This packet establishes their own instruction-level effects and the setter's insertion callee, rather than re-claiming the earlier 706-byte caller. This answers the earlier packet's next question and corrects a tempting simplification: a request whose low byte is at most 2 does **not** always get stored directly; one path computes a new 0/1 state from runtime conditions.

Read-only selection examined 576 live open PRs with `gh pr list -R lalalune/hyperliquid-source --state open --limit 1000 --json number,title,body`, and the same 576-record local snapshot. No body mentioned the three helper addresses or the global head `0x59b0e50`. PR #1916's title/body matched the general TLS topic, but its evidence scope explicitly excluded these helper bodies. This screening is not ownership or a guarantee against later work; recheck before submission.

## Reproduce

Observed environment: macOS 26.4.1 (25E253), Python 3.11.15, Apple LLVM objdump 21.0.0 (optimized build). Run from the repository root, with the pinned node94 LFS artifact materialized. The scripts use Python's standard library and a local static disassembler; they never execute the captured binary, start a node, sign, or make chain/network requests.

```sh
python3.11 research/work-items/RE-001-tls-state-membership-94/verify.py --negative-controls
python3.11 research/work-items/RE-001-tls-state-membership-94/list-witnesses.py
python3.11 research/work-items/RE-001-tls-state-membership-94/capture.py --objdump /Library/Developer/CommandLineTools/usr/bin/llvm-objdump --output work/tls-membership-recapture
```

The output directory must be new: capture refuses to overwrite earlier evidence. For another host, pass its LLVM objdump path explicitly. Compare the recaptured `evidence.json`, `frames.txt`, and four `*.objdump.txt` files with the retained files. An observed independent export to `work/tls-membership-export` reproduced all four disassembly files exactly. The scripts contain no absolute user paths, package installations or target execution.

The export runs `llvm-objdump -d --start-address=... --stop-address=... artifacts/node/94/hl-node` on the five exact ranges in `evidence.json`, plus `llvm-objdump --dwarf=frames artifacts/node/94/hl-node` and retains the three selected FDE blocks. `capture.py` is the exact reproducible command recipe, including export normalization of the input's path label. All original instruction bytes, range hashes and section-resolved file offsets are retained. LLVM's nearest-symbol annotations do not identify these functions.

`verification.json` records the successful whole-input and structural check plus six rejected mutations. `list-witnesses.json` records 14 conditional pointer-topology witnesses; this is a static interpretation control and not captured-code execution or proof of arbitrary pointer-graph correctness. The checker/parser code adapts the independently authored earlier TLS evidence checker; no inferred reference implementation is copied.

## Original boundaries and symbol bindings

All addresses are **ELF virtual addresses**. The verifier maps through file-backed ELF sections, rejects duplicate section names, and decodes the selected records only under the exact observed `zR` CIE with pcrel signed-32-bit PCs. It does not substitute unwind-index spacing for function extent.

| FDE section offset | Independently decoded range | Role |
| --- | --- | --- |
| `.eh_frame+0x2cf83c` | `0x555a4c0..0x555a688` | State setter / membership removal |
| `.eh_frame+0x2cf7a8` | `0x555a290..0x555a36d` | Membership insertion |
| `.eh_frame+0x2cf6e4` | `0x5559a90..0x5559af1` | Cached-field refresh |

LLVM's separate frame output agrees with each decoded PC/range. Every byte of these three selected FDEs is covered once by retained disassembly, including internal alignment instructions. The verifier checks all 165 retained instruction/prefix lines, 17 direct rel32 edges and 18 short/conditional branches across the helper bodies and PLT anchors. It verifies original displacement bytes and destinations; these are not a whole-program xref census.

PLT `0x5660e70` jumps through `0x5779460`, whose unique `R_X86_64_JUMP_SLOT` relocation names `pthread_mutex_trylock`. PLT `0x5660230` similarly resolves `0x5778e40` to `pthread_mutex_unlock`. Both receive `0x59b0e20` as the lock address. Nonzero trylock return invokes `0x552a500` with `0x59b0de0` (lock address minus 0x40), then continues. That helper's own effects and blocking behavior are unresolved; claiming the fallback proves mutex ownership would exceed the evidence.

## Observed setter protocol

Let `old` be the entry byte at object `+0x330`, and `requested` the second argument's **low byte** (`sil` / preserved `bpl`). Comparisons against 2 are unsigned. The full 32-bit argument is saved, but only the low byte selects and is stored by these paths.

| Entry relationship | Observed path |
| --- | --- |
| `old>2`, `requested>2` | Store `requested` at `+0x330`, then tail-call the refresher once |
| `old>2`, `requested<=2` | Store `requested` first, call insertion `0x555a290`, then tail-call the refresher once |
| `old<=2`, `requested>2` | Enter trylock/fallback protocol; perform head update and pointer surgery; clear global byte `0x59b0e48`, unlock, **then** store `requested`; tail-call refresher once |
| `old<=2`, `requested<=2` | Enter exchange/retry at `0x555a5c9`; do not directly store the requested byte; after exchange returns an old byte other than 2, call refresher and then tail-call it again |

The last row's offered byte is initially 1. It becomes `(dword[0x59b0dc0]!=0)` only when file-backed/global byte `[0x5787f80]==0`, object byte `[obj]!=0`, and signed object byte `[obj+1]<=0`. A reloaded state greater than 2 is offered directly instead of computing 0/1. `xchg r8b,[obj+0x330]` at `0x555a5c0` returns the previous byte; previous value 2 causes reload/retry. This is an x86 memory atomic exchange; no recovered source-language memory order is claimed. The loop is not a single store determined by the entry state, and concurrent changes can affect later iterations.

Both membership helpers increment qword `[0x59b0e18]` after the trylock/fallback join. If the object differs from qword `[0x59b0e10]`, they increment `[0x59b0e08]` and replace `[0x59b0e10]` with the object. These are modulo-2^64 machine additions; their higher-level profiling/ownership meaning is not established. The fallback sets byte `[0x59b0e48]=1`; the normal exit clears it to 0 before unlock. It is not named as a boolean ownership guarantee.

## Pointer-store evidence and conditional list interpretation

Use `N(x)=[x+0xc8]`, `P(x)=[x+0xd0]` and `H=[0x59b0e50]` as **notation only**. The exact sequential loads/stores below preserve possible alias effects; the pairs are not replaced with an invented struct implementation.

Insertion first writes `N(obj)=obj` and `P(obj)=obj` via one 16-byte `movups`, **before entering the trylock/fallback protocol**. If `H` is nonzero, the body then executes:

```text
rdx=P(obj); rcx=P(H); N(rdx)=rcx; P(H)=rdx;
rsi=P(obj); rdi=N(rsi); P(obj)=rdi;
r8=P(H); N(r8)=H; N(rdi)=obj;
```

It finally assigns `H=N(obj)`, clears the global byte, and tail-calls unlock. On an initially empty structure, the pointer surgery is skipped and `H=obj`. Under the explicit precondition that `H` names a valid circular doubly linked structure and `obj` is a separate valid object, these stores insert `obj` immediately before the existing head and retain that head. This is an **inference established under those invariants**, not a proof for arbitrary aliases or corrupt pointers.

Removal first tests whether `obj==H`. If so, it reads `N(obj)`: a self-link clears `H` and skips pointer surgery; otherwise `H=N(obj)` and continues. The general surgery is:

```text
r11=N(obj); r10=P(obj); rax=P(r11); N(r10)=rax;
rsi=N(obj); P(rsi)=r10;
rdx=P(obj); rdi=N(rdx); P(obj)=rdi;
rcx=P(rsi); N(rcx)=rsi; N(rdi)=obj;
```

Under valid circular-link invariants, this detaches `obj`, self-links both of its fields, and preserves a cycle among the remaining nodes. If it was the head, the next node becomes the head; the singleton case leaves no head. Calling this “removal” depends on those stated invariants; the raw operations above remain the primary observations.

`list-witnesses.py` mirrors only these target-derived load/store sequences on synthetic maps and checks an independent cycle postcondition for insertion into lists of size 0..3 and removal of every element from lists of size 1..4 (14 cases total). In particular it covers two-element aliasing and head/singleton removal; it does not establish native concurrency, memory safety, reachability or target equivalence.

## Refresher's complete visible effect

The 97-byte helper at `0x5559a90` contains no calls. If byte `[obj+0x330]` is nonzero on entry, it writes zero qwords to `+0x340` and `+0x350` and returns.

When that byte is zero, it loads qwords `+0x10` and `+0x20`. Each is independently replaced with zero if it is **unsigned greater than or equal to `0xfffffffffffff001`**; otherwise it is preserved. The two results are written to `+0x340` and `+0x350`, respectively. It then executes `lock orq $0,(%rsp)` and re-tests the state byte. A now-nonzero state clears both outputs; a zero state returns with the earlier outputs. The stack operation preserves its operand value and is an observed locked memory operation; no C/Rust fence mapping is asserted.

This does not prove the state stayed zero between both tests or that the source qwords remained stable. The upper-value clamp resembles filtering an encoded-error range, but no recovered field types or source error representation are asserted. The two cache destinations are numeric offsets, not named allocator fields.

## Validation, progress and remaining gaps

Before this contribution the state-setting and membership helpers were unresolved callees of PR #1916. Afterward, one 3-FDE / 774-byte closure maps all visible threshold paths, lock/fallback joins, exact circular-link operations, refresh stores and atomic instructions. The two PLT anchors identify actual imported symbols. The selected global addresses are `.bss` (recorded widths and membership only), except byte `0x5787f80` in `.data` whose file value is 1; its later runtime value remains unknown.

Observed checks pass full artifact identity, five exported range hashes, three FDE records, complete raw-byte coverage, edge destinations, unique selected relocations, global section identities, exact re-export and 14 synthetic topology witnesses. Six downstream mutations are rejected after bypassing only the outer artifact SHA gate: state threshold, unlink offset, insertion self-link offset, refresh sentinel, FDE range and trylock relocation. Range mutations are intentionally rejected at their exact range-byte locks; the FDE and relocation controls exercise independent structural checks.

No Cargo build, Rust source reconstruction, native behavior comparison, normalization mask, hosted CI, container run or full allocator identity is claimed. Repository-wide checks are recorded by the integrating operator separately; this packet does not invent their results. Whole-component acceptance gates remain false. The pointer interpretation requires valid cycles and object separation; fallback lock ownership, arbitrary alias cases, runtime global initialization and source-language ordering remain unknown.

Next question: establish what `0x552a500` does on trylock failure and where the global structure and its lock are initialized; then associate the numeric state/membership protocol with licensed upstream source under a validated version/fork identity.
