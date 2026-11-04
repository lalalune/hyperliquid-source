# RE-017: result-ring growth after the node 115 state-loader continuation

For the selected loader-linked block-result ring, a full ring below the existing conversion threshold grows its 64-byte rows and preserves their logical order by moving the shorter wrapped segment, choosing the tail on a tie; this makes the growth step reconstructible without flattening or re-sorting the ring.

- Component ID: `abci`; RE-017 supports the RE-009 storage and state-root investigation.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; navigation reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. The latter is unlicensed and was used as a lead only, not as implementation source. The historical RE-017 record is retained at commit `c3b77a8e84c3f2b10db7a2a69b6b66bfddea93d4`.
- Claim status: selected ELF bytes, relocations, unwind records and instruction effects are observations; their interpretation as a ring and the preservation conclusions are conditional inferences. Runtime scheduling, allocation identity and the rest of the component remain unresolved.
- Scope included and excluded: both complete new unwind-described ranges, their selected calls, three movement arms, capacity publication, a tag-1 failure boundary, and the existing caller's relevant exception landing. Previously proposed loader, block, result, insertion, lookup and collector functions are contextual boundaries, not new ownership. This is not the full begin/action/end-block or root-input gate.

## Reproduce

From the repository root on Linux x86-64, with the authenticated node #115 capture present:

```sh
python3 tools/artifacts.py verify
python3 tools/verify_imports.py
python3 tools/verify_packets.py
python3 tools/catalogue.py --check
python3 -m unittest tests.test_abci_ring_growth115
python3 tools/abci_ring_growth115.py --out research/work-items/RE-017-abci-ring-growth-115
mkdir -p work/re017-growth-check/bin
ln -sf "$(command -v python3)" work/re017-growth-check/bin/python3
PATH="work/re017-growth-check/bin" PYTHONHASHSEED=1 TZ=UTC python3 -m unittest tests.test_abci_ring_growth115
PATH="work/re017-growth-check/bin" PYTHONHASHSEED=1 TZ=UTC python3 tools/abci_ring_growth115.py --out work/re017-growth-check/one
PATH="work/re017-growth-check/bin" PYTHONHASHSEED=314159 TZ=Pacific/Honolulu python3 tools/abci_ring_growth115.py --out work/re017-growth-check/two
diff -r work/re017-growth-check/one work/re017-growth-check/two
diff -r -x README.md -x MANIFEST.sha256 work/re017-growth-check/one research/work-items/RE-017-abci-ring-growth-115
(cd research/work-items/RE-017-abci-ring-growth-115 && sha256sum -c MANIFEST.sha256)
```

Use initially empty output directories. The generator authenticates the complete #115 input before output, imports the repository's ELF and FDE readers, excludes `SHT_NOBITS` and non-allocated sections from VA mapping, and uses only the Python standard library. It makes no external-program calls and does not execute either captured binary. Python 3.12.3 was used for generation and tests; GNU objdump 2.42 was used solely for human inspection. Its output is not an input to the generator or tests. The two regeneration commands vary both hash seed and timezone; the separate Python-only search path contains no binutils.

If the retired capture is independently available, the following optional command authenticates it separately and checks the old Location, caller, target and FDEs. It writes the same #115 evidence; #94 is never substituted for the target.

```sh
python3 tools/abci_ring_growth115.py --historical-node references/can1357-hl/bin/hl-node-mainnet-new --out work/re017-growth-check/historical
```

`functions.tsv` contains complete raw bytes and hashes for the two selected FDE ranges. `windows.tsv`, `transfers.tsv`, `relocations.tsv`, `location.tsv` and `unwind-context.tsv` retain the scoped raw observations and file offsets. `synthetic-examples.tsv`, `synthetic-history.tsv` and `synthetic-counterfactual.json` are explicitly modeled inputs, not execution traces. `summary.json` gives the selected-record counts and bounded-model totals. `MANIFEST.sha256` covers this README and every generated evidence file.

## Evidence

All addresses below are linked ELF virtual addresses before rebasing; generated tables also include file offsets. The two starts and exclusive ends are reconciled with both `.eh_frame` and `.eh_frame_hdr`. An FDE describes an unwind interval, not necessarily an original source-function boundary, all code paths, or all callers. The two complete intervals contain 252 bytes in total; the ten new windows partition those bytes without gaps or overlap. This byte partition is not a complete control-flow proof.

### Context and ownership

Prior pending proposals describe the conditional chain from the #115 `state.rs:123:37` Location through loader `0x3c12800`, the expanded owner, a selected begin/item/end block path, and projected result rows. The loader and begin instructions checked here are context, not re-owned findings. The earlier result bridge and sort proposals identify an accumulator, `0x4dd0010`, and an insertion boundary, `0x57ea380`. The new finding starts at the growth callee of that existing insertion. The location-to-result chain depends on their separately stated dispatch, normal-return and alias assumptions; it is not a captured execution or proof that one runtime object traversed the chain.

In the earlier proposed startup path, `0x2cb6500` and `0x2cbbbe0` lead through `0x2b41b70` to `0x3c12800` and the Location wrapper. Other pending proposals describe a returned-state constructor `0x5a6bfb0`, owner callback `0x5a6e1e0`, and selected block lane through `0x4f122c0`, `0x4fcb590`, `0x56186c0` and `0x5a06600`; their begin and end boundaries include `0x5483f50` and `0x5a08720`. A separate proposed result continuation relates projector `0x5961310`, zipper `0x5b30c10`, accumulator `0x4dd0010` and collector `0x5b785d0`. These are cited context from PRs #2047, #2107, #2132, #2243, #2352 and #2359, not new ownership or proof that the result rows are the state root. Each join remains conditional on the cited branch, binding and alias assumptions.

| Stage | Observation and scope |
| --- | --- |
| Existing state Location | `0x3c1352f` addresses Location `0x64767a8`, whose relocated string ends in `l1/src/abci/state.rs` and whose line/column are 123/37. The following comparison uses 1. |
| Existing block and result context | The earlier begin path at `0x5483fd3` includes the selected `+0x28` saturating increment and other stores. The result accumulator's lookup and threshold window begins at `0x4dd0177`; the previous bridge records a later 64-byte-row collector at `0x5b78628`. The component's complete state and root relation remains open. |
| Existing insertion to new growth | An unsigned index greater than the length branches from `0x57ea392` to a diagnostic call followed by `ud2` if that call returns. Otherwise, an insertion whose length equals capacity uses the previous call `0x57ea3a9` through slot `0x64e5e60`. Its unique relative relocation has addend `0x5800d70`. These existing calls, branches and slot are context, not new ownership. |
| New wrapped-buffer helper | `0x5800d70..0x5800e08` saves the old capacity, calls a capacity helper and, after its normal return, tests whether rows wrap and whether to move the tail or prefix. |
| New capacity helper | `0x5962d20..0x5962d84`, reached through slot `0x64ebf50`, selects the new capacity, supplies alignment 8 and element width 64 to the direct boundary `0x5963650`, and branches on the returned 32-bit tag. That callee is a shared boundary, not a selected FDE here. |

The previously proposed lookup returns the selected hit/miss values 0/1. With that contract, a miss below 64 reaches insertion; a miss at or above 64 takes the existing ring-to-tree conversion, while a hit takes replacement. The `0x40` threshold and these contextual instructions are checked independently in `windows.tsv`. The full-ring growth call therefore sees old capacity and count below 64 on that selected, well-formed ring route. This does not establish reachability of every capacity or any tree-to-ring transition.

### Growth and wrap decision

For this table only, write `C` for the old capacity at descriptor `+0`, `P` for the buffer pointer at `+8`, `H` for the head at `+0x10`, and `L` for the length at `+0x18`. The caller supplies a well-formed descriptor, and the capacity helper and copy bindings are assumed to return normally without conflicting alias writes. The interpretation of these words is inferred from the operations and the prior result-ring evidence.

| Condition or return | Byte-backed operation |
| --- | --- |
| Capacity candidate | `0x5962d2d` forms `2*C` in 64-bit arithmetic. `0x5962d31..0x5962d3f` uses that wrapped value when it is at least 5, otherwise 4. For the selected `C < 64`, this is `max(4, 2*C)`, without arithmetic wrap. |
| Capacity result tag is not 1 | `0x5962d60..0x5962d6c` stores the returned word to `P` and the candidate to `C`, then returns. The 64-bit word at `+0x18` is not written by either new FDE on its inspected normal path, subject to effects of called helpers and aliases. |
| `H <= C - L` | The old occupied rows do not wrap. `0x5800d92` reaches the return without a relocation copy or a head write. |
| `H > C - L`, and `t <= p` or `C' - C < p` | Let `t = C - H`, `p = L - t`, and `C'` be the new capacity. The code passes `t * 64` bytes at old index `H` to the relocation named `memmove`, places them at index `C' - t`, and stores `H = C' - t` after that call. |
| `H > C - L`, `t > p`, and `C' - C >= p` | The code tail-calls the relocation named `memcpy` for `p * 64` bytes from index 0 to index `C`; it does not change `H` on that arm. The selected conditions put the destination in the new space and keep the source and destination disjoint. |

The two memory names come from distinct `R_X86_64_GLOB_DAT` entries and `.dynsym`/`.dynstr`, not guessed GOT labels. The runtime loader's actual bindings and their conformance to the usual copy contracts remain assumptions.

The key instruction sequence is reproduced from selected #115 bytes, with objdump used only for this human-readable excerpt:

```text
5800d8c  48 29 d0             sub    rax,rdx
5800d8f  48 39 c6             cmp    rsi,rax
5800d92  76 51                jbe    0x5800de5
5800da0  48 39 d0             cmp    rax,rdx
5800da3  0f 96 c1             setbe  cl
5800dac  48 39 d7             cmp    rdi,rdx
5800daf  40 0f 92 c7          setb   dil
5800ddb  ff 15 87 e7 cd 00    call   [0x64df568]
5800de1  4c 89 7b 10          mov    [rbx+0x10],r15
5800e02  ff 25 00 e7 cd 00    jmp    [0x64df508]
5962d5a  83 3c 24 01          cmp    dword [rsp],1
5962d5e  74 14                je     0x5962d74
```

For a valid **full** ring, `L = C` and, if it wraps, `p = H` and `t = C - H`. On the selected `C < 64` path the new capacity is at least `2*C`, so `C' - C >= p`. The extra-space clause cannot force the tail: the tail is selected exactly when `t <= p`, including equality. The no-wrap arm retains `[H, H+L)`; the tail arm presents `[C'-t, C')` followed by `[0, p)`; the prefix arm presents `[H, C)` followed by `[C, C+p)`. In each case those are the original rows in the same logical order. The argument assumes valid indices, unchanged buffer contents on successful growth, appropriate copy bindings and no interfering aliases.

The bounded model checks all 87,361 valid `(C,H,L)` combinations for `C` from 0 through 63, including 2,017 full-ring descriptors, with zero logical-row mismatches. These are synthetic finite checks, not target executions; the interval argument above explains the general relation within the stated preconditions. One counterfactual `C=8, H=3, L=8, C'=10` has insufficient extra space for the shorter prefix and selects the longer tail. This counterfactual is useful for the actual branch rule but cannot arise from the selected small-capacity doubling rule.

`synthetic-history.tsv` separately models 64 descending distinct keys, one existing-key replacement, then an absent key. Under the **assumed prior** lookup and insertion/move contracts, the capacity sequence is 4, 8, 16, 32, 64; the hit at count 64 replaces, and the following miss reaches conversion without another ring growth. This is an illustrative model of the conditions, not evidence that the scheduler produces those keys or that every insertion, deletion, conversion or unwind preserves the global sorted/unique invariant.

### Failure and unwinding

In `0x5962d20`, tag 1 branches before the helper's two descriptor stores. The failure arm loads two returned words and calls the boundary selected by relative slot `0x64df498`, addend `0x141e264`. The next byte at `0x5962d84` is `int3` and lies just beyond the FDE's exclusive end. The FDE does not establish whether that boundary returns, aborts, or unwinds; it also does not prove allocator rollback or exclude mutations by callees through aliases.

Neither new FDE has an LSDA. The separately decoded prior insertion LSDA covers its growth call and names landing `0x57ea496`; that landing calls the previously identified cleanup boundary `0x57da4e0` and then the unwind-resume boundary. Thus, **if** an exception propagates through the recorded call-site range under the expected personality, this is the selected caller landing. The LSDA action field is retained but its action chain, cleanup completeness and any changes made before the exception are not proved. No new claim is made on the prior insertion body or its existing call sites.

### Historical cross-check

The older #94 finding remains bound to SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`: caller `0x32725d0`, call `0x3272785`, relative slot `0x57755a8`, callee `0x3273810`, and Location `0x56dfbf8` with line 107, column 37. The callee's selected comparison at `0x3273871` uses 2. The optional check was run against that separately authenticated historical capture, including its own FDEs and bytes. The independently authenticated #115 record above instead uses Location `0x64767a8`, line 123, column 37, and compares a different returned register with 1. Similar source suffixes are navigation evidence; no address, tag, layout or behavior is transferred between releases or asserted equivalent.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo manifest/lockfile, compiler and linker flags, two-build comparison, raw/normalized implementation comparisons, masks, helper and dynamic-binding closure, runtime fixtures, relocation/vtable/data closure and whole-ELF equivalence are not yet implemented or measured. No node or visor was run, and there were no node-network, key or chain operations.

## Results and limitations

The extractor records 2 new FDE ranges, 10 new instruction windows plus one boundary byte and 8 context windows, 8 new selected transfers plus 9 context transfers, 6 relocation records and one prior call-site/landing match. These are selections, not a function or component coverage denominator. The focused suite has 41 passing tests and zero skips, including wrong and same-size-mutated SHA-256, every selected window and transfer opcode/displacement, missing or overlapping FDE windows, FDE and LSDA corruption, duplicate/malformed relocations, symbol damage, invalid/overlapping/NOBITS mappings, growth bounds, tie and insufficient-space controls, independently checked row order, and bounded synthetic lifecycle cases. A separate synthetic sweep checks smaller growth increments and overlapping tail moves. Artifact, import, packet-manifest and catalogue checks passed; the packet-manifest check covered 29 manifests and 467 entries with this packet present. Tests and models do not execute target instructions.

No progress gate is requested. The complete allocator boundary, concurrent/alias effects, all insertion and tree conversions, error action chains, actual root bytes, all begin/action/end variants and live state persistence remain unresolved. Next question: without re-owning the prior insertion or generic allocation bodies, establish the selected allocation boundary's failure contract and prove that all representation transitions preserve the ring's ordering and ownership invariants.
