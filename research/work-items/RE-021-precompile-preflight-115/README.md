# RE-021: node 115 precompile preflight and address-09 account policy

The reconstruction can now distinguish the address-09 account-policy membership check and its cache-journal consequence from the later BLAKE2b callback lookup, while applying the observed validation, initial cost and payer-balance decisions before that lookup.

- Component ID: `evm`; RE-021 is a bounded extension of RE-011, not an official task-table row.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; reviewed historical #94 compression packet at `2fff9c5e02c5ecd6cb5062f1b23442b5ba712104`. No unlicensed reference code was copied.
- Claim status: selected ELF bytes, FDE intervals, relative branches, relocations, literal bytes and exception call-site records are observations; roles, the conditional data flow, the arithmetic and account-policy interpretations are inferences; actual runtime state and the remaining callees are unresolved.
- Scope included and excluded: the selected transaction's preflight, one mode-13 schedule, the account cache and the compact account-policy test that can consume address 09. The previously mapped caller, registry, BLAKE2b callback and post-frame logic are boundaries, not newly owned FDEs. This is not a complete EVM dependency/fork matrix, transaction implementation, backend storage analysis, execution trace or whole-component gate.

## Reproduce

From the repository root with Python 3.12.3 and the authenticated #115 artifact:

```sh
python3 tools/re21_preflight115.py --out research/work-items/RE-021-precompile-preflight-115
python3 -m unittest tests.test_re21_preflight115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-precompile-preflight-115 && sha256sum -c MANIFEST.sha256)
```

For two separate output directories, replace the bracketed placeholders with writable relative directory names:

```sh
python_exe=$(command -v python3)
PATH= PYTHONHASHSEED=0 TZ=UTC "$python_exe" tools/re21_preflight115.py --out <tmp-dir-a>
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$python_exe" tools/re21_preflight115.py --out <tmp-dir-b>
PATH= "$python_exe" -m unittest tests.test_re21_preflight115
diff -r <tmp-dir-a> <tmp-dir-b>
```

Optional cross-release static check, if the independently authenticated historical artifact is present:

```sh
python3 tools/re21_preflight115.py --out <tmp-dir> --legacy references/can1357-hl/bin/hl-node-mainnet-new
```

The generator checks the complete #115 SHA-256 before parsing. The optional input has its own #94 SHA-256 check. It uses Python's standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`, excludes SHT_NOBITS from file-byte mapping, and does not execute the node, captured machine code or external programs. GNU objdump 2.42 was used for human inspection only; its output is not parsed into evidence or tests. The generator writes the 15 generated data files and does not modify this README or MANIFEST. The manifest covers every other file in this work-item directory.

## Evidence

All code and data coordinates below are ELF virtual addresses (VAs), not relocated process addresses. `functions.json` gives file offsets, raw body bytes, FDE and CIE bytes and actual FDE intervals with exclusive ends. `windows.tsv` records selected fixed-byte instruction windows, `edges.tsv` selected direct relative transfers, `immediates.json` recognized instruction operands, `rip-references.tsv` selected RIP-relative operands, and `relocations.json` the relevant `R_X86_64_RELATIVE` slot/addend pairs. These are selected observations, not exhaustive disassembly or proof that FDE boundaries identify every source function. Full FDE body bytes are retained to support independent review.

### Selected FDEs

| Inferred role | Start VA | End VA, exclusive |
| --- | --- | --- |
| Environment validation | `0x2b92c10` | `0x2b93026` |
| Input cost admission | `0x2b93030` | `0x2b931c1` |
| Cost calculation | `0x5be0720` | `0x5be0a92` |
| Mode to schedule cache | `0x5be0aa0` | `0x5be0cac` |
| Mode-13 once adapter | `0x5be2a93` | `0x5be2adc` |
| Schedule initializer, descriptor slot +`0x18` | `0x5be2ce0` | `0x5be2d11` |
| Schedule initializer, descriptor slot +`0x20` | `0x5be29d0` | `0x5be2a01` |
| Schedule allocation and coefficients | `0x5be2560` | `0x5be29c7` |
| Payer account and code wrapper | `0x299f4d0` | `0x299f676` |
| Account cache loader | `0x4323870` | `0x4323f10` |
| Account map entry | `0x3ed7040` | `0x3ed71a8` |
| Account policy membership | `0x5bdf8e0` | `0x5bdf9f7` |
| Policy associated-map membership | `0x5bdef30` | `0x5bdf01f` |
| Policy fallback-map membership | `0x5bdf020` | `0x5bdf10f` |
| Recipient account and code wrapper | `0x2971760` | `0x2971888` |
| Payer budget and balance | `0x2973440` | `0x29738de` |

### Handoff to the existing address-09 route

The previously mapped driver FDE is `0x29a1290`; its body is not included as a selected function here. Short boundary windows and direct call edges establish the handoffs to the new functions. It calls validation at `0x29a1bca`, accepts the `0x25` result, then calls the cost admission helper at `0x29a1c56` and accepts `0x21`. It calls the payer wrapper and balance helper at `0x29a1cdb` and `0x29a1d84`, respectively. A separate branch calls the recipient wrapper at `0x29a2e70`, passing a code-request byte of 1 and loader mode byte 0. These windows do not claim that earlier validation guarantees all later calls return normally.

On the selected recipient branch, the context byte at +`0x1dc` is 1. The 20 input bytes at context +`0x1dd` are copied through a temporary into a frame field at +`0x90`. The prior lookup boundary at `0x2a6bc5d` addresses that same frame field. `input-lineage.json` derives the stack displacements from the instruction bytes; it also connects the cost helper's input pointer and length to the arguments supplied to a later dynamic clone. The prior BLAKE2b lookup packet, RE-021-blake2b-lookup-115 (PR #2049), maps the subsequent registry selection, lookup, callback and frame outcomes. Composition with it assumes the dynamic clone and allocation return normally, the constructed frame is used, no intervening alias mutates the bytes or key, and the registry is initialized and retained. Those assumptions are not a runtime observation.

Independently, `address-anchor.json` checks the #115 source record at VA `0x64c0730`, file offset `0x64be730`: its 20 bytes at +`0x20` are 19 zero bytes followed by `09`, and the relocation at +`0x18` has addend `0x5c165b0`. This is a boundary identity check for the existing callback, not a reanalysis of its FDE. The account-policy membership structure below is separate from that callback registry: their contents, lifetime and initialization must not be assumed identical.

### Account-policy membership for address 09

The account loader calls the policy function through slot `0x64ea6d8`, whose relocation addend is `0x5bdf8e0`. The following table describes its selected ordered normal-return path, using `P` for its first pointer and `K` for a 20-byte key. The byte comparison and direct branches are in the `member_*` windows and `edges.tsv`.

| Condition, after earlier rows fail | Observed decision |
| --- | --- |
| `P[+0x68] == 1` and its 20 bytes at +`0x69` equal `K` | Return 1. |
| Associated map at `P+0x28` contains all 20 bytes | Return 1; the map helper is `0x5bdef30`. |
| `P[+0x18] == 0` | Return 0. |
| First 18 bytes of `K` are zero and its big-endian final 16 bits are below 300 | Use the compact bit representation described below; an out-of-range index calls a separate error helper. |
| Other key and `P[+0x7d] != 0` | Return 0. |
| Other key and `P[+0x7d] == 0` | Tail-call the fallback map membership function `0x5bdf020`. |

The associated and fallback maps use the same 16-control-byte grouped search pattern, but their observed bucket strides are 64 and 20 bytes, respectively. They return 0 or 1 after a full 20-byte equality check. Both read a process secret through a relocated pointer; the addend `0x64ffe90` is SHT_NOBITS, not a file-backed value. The model accepts a synthetic secret rather than claiming one from the ELF.

For the compact arm, let `n = int.from_bytes(K[18:20], 'big')`, `p = P[+0x50]`, and `L = P[+0x58]`, with both `p` and `L` read as 64-bit words. The branch checks `n < (L >> 3)`; otherwise it calls `0x5bdfa00`. For a valid backing representation the byte instructions compute `i = 8*(p & 7) + (L & 7) + n`, load a 64-bit word at `(p & ~7) + 8*(i >> 6)`, and return bit `i & 63`. The split between the packed pointer and length fields is a byte-level calculation, not a claim about their original Rust types.

`membership-layout.json` reads the bound and bit parameters from #115 instructions and the key from the #115 record. Thus address 09 has `n = 9` and qualifies for the compact-key shape. It reaches this arm only if the special key and associated-map tests miss and `P[+0x18]` is nonzero. The actual `P`, bit length and bit value are unavailable statically; neither 0 nor 1 is asserted for a live node. The `< 300` rule also does not establish that every eligible address has an installed callback.

### Cache load, journal and code selection

`0x3ed7040` checks a 20-byte account key in a 16-control-byte grouped map. Its hit returns a zero first word and an entry pointer; on a miss it returns a vacant-entry description, calling a reserve helper if the capacity field is zero. The observed account bucket stride is `0xa8`. With synthetic values, its unsigned hash can be expressed as `fold(fold(k0 XOR seed, k1 XOR secret) XOR k2, secret)`, where `k0` and `k1` are the first two little-endian 64-bit words, `k2` is the remaining little-endian 32-bit word, and `fold(a,b)` is the XOR of the low and high 64-bit halves of the 128-bit product. The fingerprint is the hash shifted right 57 bits. This describes the selected helper, not a claim that the process secret is fixed.

The loader uses the key and its state pointer to select these outcomes:

| Path | Observed state or control effect |
| --- | --- |
| Existing entry with current 32-bit epoch and flag `0x10` clear | Return the entry without the refresh branch. |
| Missing entry | Call the policy helper, then call the backend boundary `0x3d48970`; the result selects either a copied account-shaped value or a default-shaped value before insertion. The selected code writes control bytes, key/value data and a count in an `0xa8`-stride map. Backend semantics remain unresolved. |
| Missing entry, policy result 0 | Before insertion, append a journal record with tag 0 and the 20-byte key; if the journal is full, call the capacity helper first. |
| Missing entry, policy result 1 | Bypass that new-entry journal append. |
| Existing entry with different epoch or flag `0x10` set | Recheck policy; on the accepted path, copy the current epoch, clear flag `0x10`, optionally call a helper for flag `0x40`, clear flags `0x40` and `0x80`, and append a tag-0/key journal record. |
| Policy gate rejects | Write result byte 2. The payer wrapper sends this result to a separate error helper; the recipient wrapper returns from its early branch. Their complete error payload and helper behavior remain unresolved. |

The two selected wrapper handoffs use loader mode 0. Given the observed boolean policy results and normal returns, that mode does not reject on the membership result: the membership bit instead determines whether the missing-entry journal append occurs. Other caller modes can reject; no claim is made about a particular runtime cache miss or journal content. In a separate step, when the account +`0x70` pointer is zero, the wrappers compare the 32 bytes at +`0x48` with two file-backed literals. Matching halves choose a shared default object; a mismatch calls the code-fetch boundary `0x43c8ec0`. The recipient wrapper performs this step only when its code-request byte is nonzero. `code-digest-literals.json` shows that the concatenated comparison halves equal the 32-byte literal used in the loader's default-shaped account. It does not prove the source hash algorithm or that backend code loading succeeds.

### Validation and failure precedence

`0x2b92c10` receives the context at its second argument. The following observations are conditional on earlier branches allowing the row to be reached; offsets below are relative to that context and result tags are raw integers, not source enum names.

| Reached predicate | Observed result or next step |
| --- | --- |
| Revision byte +`0x268` > 8 and bit 0 of byte +`0xbc` is clear | Tag `0x21`, result byte +8 = 0. |
| Revision > 10 and both first 64-bit context words are zero | Tag `0x21`, result byte +8 = 1. |
| Network check enabled at +`0x260`, kind word +`0x100` equals 1, and the two checked words at +`0x108` and +`0x258` differ | Tag `0x0c`. |
| Network check enabled, kind word +`0x100` is not 1, and type byte +`0x1f1` is 1 through 4 | Tag `0x0d`. |
| Byte +`0x265` is zero and value +`0x1b8` exceeds the active limit | Tag `0x0e`; the optional override is +`0x248`, otherwise revisions at least 13 use `0x1000000` and older revisions use the maximum 64-bit value. Equality passes this check. |
| Type byte +`0x1f1` is in 0 through 4 | Dispatch via the five signed relative entries in `tables.json`; indices 1, 2 and 4 require revisions above 6, 7 and 11, respectively. Index 3 requires the earlier revision/word condition. Failure tags are `0x1a`, `0x1b`, `0x1d` and `0x1c`, respectively. |
| Byte +`0x262` is zero and word +`0x1b8` exceeds word +`0x90` | Tag `0x02`. |
| Revision at least 10, byte +`0x1dc` is zero, no custom threshold, and word +`0x200` is not 1 | Compare word +`0x120` to 49152 for revisions 10 through 13, or 65536 for revision at least 14; a larger value returns `0x0b`. |
| Final sentinel word +`0x1c0` is all ones | Tag `0x08`; otherwise the ordinary successful path writes `0x25`. |

For the following comparisons only, assume bytes +`0xe0` and +`0x264` are canonical 0/1 flags. Let `X` be the little-endian 128-bit quantity at +`0x130`, `Y` the 128-bit quantity at +`0xf0`, and `M` the unsigned word at +`0x98`. For indices 0 and 1, `X < M` with +`0x264` clear returns tag 1. For indices 2, 3 and 4, `X < Y` with +`0xe0` set returns tag 0 first; otherwise `X < M` with +`0x264` clear returns tag 1. Equality passes these comparisons. For type 4, after those checks, a zero word at +`0x1b0` returns `0x19`. The binary uses raw byte operations, so the model does not claim these simplified predicates for noncanonical flag values.

For type 3, after its earlier revision and comparison checks, bit 0 of the first context byte enables another 128-bit comparison: a value at +`0x160` below the value at +`0x10` returns `0x12`. Then the word at +`0x198` is a count and +`0x190` a pointer to 32-byte records. A zero count returns `0x13`; otherwise the first byte of every record must be 1 or the result is `0x16`. Only after that scan, if bit 0 of +`0x220` is set and the count exceeds +`0x228`, the result is `0x15`. The list model assumes the backing memory is materializable and the count's left shift by five does not overflow. Other exceptional helpers and the original enum names remain unresolved.

### Schedule, cost admission and payer balance

The prior default-context constructor passes mode 13 through slot `0x64e96d8` to `0x5be0aa0`. `tables.json` reads selector cell 13 at `0x9421c8`, which targets `0x5be0b26`. The selected once adapter references descriptor `0x64bf460`; its +`0x18` and +`0x20` relative slots lead to the two selected initializers, both of which call `0x5be2560`. The arithmetic below assumes ordinary relocation and normal once initialization and that this schedule is the one received by the cost helper. It does not establish the live configuration or rule out intervening replacement.

`schedule.json` derives the selected mode-13 allocation fields from instruction immediates and file-backed data. On this schedule, for a valid materializable input slice with `z` zero and `n` nonzero bytes, `a` address items, `s` slot items and `q` auxiliary items, and assuming the relevant context flags permit those counts:

```text
tokens = z + 4*n
initial = 21000 + 4*tokens + 2400*a + 1900*s + 25000*q
if create: initial += 32000 + 2*ceil(input_length/32)
floor = 21000 + 10*tokens
```

These are inferred arithmetic meanings of the selected coefficients, not verified source field names. On the address-09 call-form branch, the selected create predicate is false. The cost helper has checked arithmetic and separate failure calls; the `input_length + 31` expression itself has no explicit overflow branch, so the equation is restricted to valid lengths. Other schedules and helper modes can change the calculation.

For the selected mode-13 admission, with the caller's floor-disabling argument clear, `initial > gas_limit` returns tag 3 first; otherwise `floor > gas_limit` returns tag 4. Equality is accepted by each comparison. There is a further conditional ceiling comparison when its separate flag is enabled; its limit and current runtime value are not established. As a synthetic check only, 213 bytes consisting of big-endian rounds 12, 208 zero bytes and final byte 1 have 211 zero and 2 nonzero bytes, giving `initial = 21876` and `floor = 23190` when `a = s = q = 0`. Limits 21875, 21876, 23189 and 23190 produce model tags 3, 4, 4 and `0x21`, respectively. This is not a node execution, callback gas result or BLAKE2b digest.

For the payer helper let `B` be the 256-bit input account value, `G` the 64-bit word at transaction-subobject +`0xd8`, `P` the 128-bit value at +`0x50`, `V` the 256-bit value at +`0x60`, and `K` the byte at +`0x111`. These names describe observed arithmetic roles, not recovered source types. The following table is ordered; additions and multiplications use the indicated unsigned widths.

| Reached condition | Observed payer-helper behavior |
| --- | --- |
| `G*P` does not fit 128 bits, or `(G*P)+V` does not fit 256 bits | Return tag 7. |
| `K == 3` and the word `N` at transaction-subobject +`0xb8` has a nonzero `N >> 47` | Call the separate error helper at `0x297389e`; no ordinary tag is established. |
| `K == 3`, with `U = N << 17` | Add `min(2^128-1, U*Amax)` to the required balance, where `Amax` is the 128-bit value at transaction-subobject +`0x80`; overflow of the 256-bit required balance returns tag 7. |
| `B` is below the resulting required balance | Return tag 6 after constructing two 32-byte diagnostic values. |
| `K >= 2` and bit 0 of transaction-subobject byte +0 is set | Use `min(P, min(2^128-1, T+S))` as the effective price, where `T` is the 128-bit value at transaction-subobject +`0x10` and `S` the 64-bit context word +`0x98`; otherwise use `P`. The required-balance check still used `P`. |
| `K == 3` and bit 0 of context byte +0 is set | Add the actual auxiliary charge `min(2^128-1, U*Aactual)`, where `Aactual` is the 128-bit context value at +`0x10`; otherwise the actual auxiliary charge is zero. |
| Effective charge or its 256-bit addition with `V` and the actual auxiliary charge overflows | Call the separate error helper at `0x2973855`; its full behavior is unresolved. |
| Normal return | Return tag `0x21` and `max(0, B - G*effective_price - actual_auxiliary_charge)`. The helper also writes a wrapped subtraction to its mutable argument before producing the clamped output. |

For `K < 2`, the auxiliary charge is zero and the effective price is `P`, giving `B-G*P` after the prior balance check. For type 3, the validation comparison described above can constrain the actual auxiliary price relative to its cap, but this packet does not assume those flags or values in all contexts. The synthetic model is restricted to `K` values 0 through 4 and also exercises deliberately inconsistent values to cover the clamp and error-helper branches. Allocation, diagnostics and unwinding are not fully resolved. The output is a helper result; this packet does not claim whole-transaction persistence or rollback.

### Cross-release and exception evidence

The historical #94 input is bound to SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Its 48-byte record at VA `0x574f0a8` (file offset `0x574d0a8`) contains the address-09 key at VA `0x574f0c0` (file offset `0x574d0c0`), and its relocation at `0x574f0b0` points to `0x4e9d2a0`. The optional check also reads the #94 validation success instruction at VA `0x1e6c427` (file offset `0x1e6b427`), whose stored tag is 25. The independently selected #115 validator stores 37 at `0x2b92faa`; these are raw tags in different release-specific contexts, not a claim that their enclosing result types or callers are identical. The #94 compression packet's candidate `0x4e9a8a0` remains a historical clue; this packet neither executes nor transplants it.

`exceptions.json` retains four selected LSDA headers and their 18 call-site records, with raw encodings and landing addresses. In particular, the account wrappers contain cleanup landing sites and the loader has cleanup and resume paths. Action chains, external destructors, allocation failure semantics and complete unwind behavior remain unresolved. `source-locations.json` preserves sanitized binary diagnostic path suffixes and coordinates; these labels do not establish exact vendored versions or copied source.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependency graph, compiler/linker flags, two-build comparison, masks, relocation/helper closure, native differential testing and whole-ELF equivalence: **not yet implemented or measured**.

The focused Python suite has 41 passing tests and no skips. It compares generated files byte for byte with the packet and checks a corrupted target hash, mutated instructions and literals, duplicate or missing FDEs and relocations, malformed exception tables, non-file-backed and out-of-range reads, address-09 compact-bit bounds, grouped map collisions and termination, type-3 error precedence, and synthetic admission/payment boundaries including auxiliary saturation. The grouped-map model assumes a power-of-two logical capacity of at least 16 and does not model mirrored physical control bytes. Hash arithmetic is cross-checked against a separate 32-bit-limb oracle. The cost, payment and compact-bit examples use synthetic inputs; they do not execute the captured target.

## Results and limitations

`summary.json` records 16 selected FDEs totaling 8864 bytes, 95 selected byte windows, 98 selected direct transfers, 17 recognized immediate operands, 27 RIP references, 17 relative relocations, five validation type-table entries, four source descriptors and 18 call-site records across four LSDAs. The windows and transfers include explicitly labelled boundary anchors. These are local evidence counts, not total function coverage, matched windows or a reconstruction percentage. The upper driver, BLAKE2b lookup and callback remain previously owned boundary evidence, and the bitmap's runtime contents are unknown. No component gate is requested or advanced.

Next question: trace how the account-policy compact bit representation is populated for address 09 and prove whether it is derived from the same activation inputs as the later callback registry, while keeping the two object identities separate.
