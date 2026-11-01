# RE-006: deletion from a per-user order index on node 94

This packet makes it possible to reconstruct the key-and-value deletion and B-tree repair performed on a per-user order index during cancellation, including predecessor replacement, sibling selection, occupancy boundaries, and root contraction.

- Component ID: `orderbook`, task `RE-006` (book transitions).
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is unlicensed and was used only for leads, not as implementation or proof.
- Claim status: byte sequences, FDE entries and relocation records are observations; function roles, data structure and order-related names are inferences. Runtime effects and value variants remain unresolved.
- Scope included and excluded: the two deletion wrappers, their shared handle deletion, leaf deletion and both sibling-borrow helpers; two immediate cancellation call sites are context only. The user lookup implementation, other order-removal effects, matching, insertion and the whole-node image are outside this packet.

## Reproduce

From the repository root, with Python 3.12.3 on Linux x86-64 and the captured target available at the relative artifact name above:

```sh
python3 tools/artifacts.py verify
python3 tools/book_user_index_delete94.py --out research/work-items/RE-006-user-index-delete-94
python3 -m unittest tests.test_book_user_index_delete94
python3 tools/catalogue.py --check
(cd research/work-items/RE-006-user-index-delete-94 && sha256sum -c MANIFEST.sha256)
```

For two fresh output directories, replace `<tmp-dir>` with a relative scratch directory:

```sh
PYTHONHASHSEED=0 TZ=UTC python3 tools/book_user_index_delete94.py --out <tmp-dir>/a
PYTHONHASHSEED=4242 TZ=Pacific/Honolulu python3 tools/book_user_index_delete94.py --out <tmp-dir>/b
diff -r <tmp-dir>/a <tmp-dir>/b
diff -r -x README.md -x MANIFEST.sha256 <tmp-dir>/a research/work-items/RE-006-user-index-delete-94
```

The generator checks the complete input SHA-256 before parsing. It imports the repository's ELF-section and FDE parsers, excludes `SHT_NOBITS` from file-backed address resolution, and reads the remaining records and selected instruction bytes directly. It starts no external process and does not execute the target. A GNU binutils 2.42 disassembly was used for the human interpretation, but is neither an input nor an output of the generator. `MANIFEST.sha256` supplies hashes of the README and all generated files.

## Evidence

All addresses below are linked ELF virtual addresses (VAs), with half-open FDE ranges. File offsets, FDE/CIE VAs, body hashes and complete raw bytes are in `functions.tsv` and `function-bytes.tsv`. For these six executable-section ranges the file offset is the VA minus `0x1000`; the generator resolves this through section headers rather than assuming it. An FDE establishes the recorded unwind extent, not completeness of the binary's functions or independent source-level boundaries.

| Inferred role | Start VA | End VA | Body bytes |
| --- | ---: | ---: | ---: |
| Perpetual-market wrapper | `0x28660a0` | `0x2866413` | 883 |
| Spot-market wrapper | `0x2866870` | `0x2866be3` | 883 |
| Delete located handle | `0x1b22a90` | `0x1b22d6a` | 730 |
| Delete leaf and repair | `0x1b17160` | `0x1b17e10` | 3248 |
| Borrow from left | `0x1af72d0` | `0x1af7617` | 839 |
| Borrow from right | `0x1afcfe0` | `0x1afd39e` | 958 |

`calls.tsv` records ten checked direct calls: two from immediate caller context, two from wrappers to the shared handle routine, two handle-to-leaf paths, and four leaf/ancestor calls to the borrow helpers. At context sites `0x26de5a4` and `0x26df5fa`, the preceding `lea` supplies the lookup result plus `0x38`; the surrounding code also addresses the book member at `+0xb8`. The existing `RE-006-user-book-cancel-94` packet identifies this as the user's second u64-keyed tree and explicitly excludes its deletion. The cancellation and spot/perpetual descriptions here rely on that context and `RE-006-order-modify-path-94`; they are not symbol names established by these six FDEs. The other packet proposes that this second tree may contain trigger orders, but its exact contents are not established here.

The selected instruction sequences in `witnesses.tsv` support the following layout. `+` means an offset from the particular tree header or node, not from the book.

| Structure | Observed access | Inference |
| --- | --- | --- |
| User entry | tree header `+0x38` | second per-user index |
| Tree header | pointer `+0x00`, qword `+0x08`, qword decremented at `+0x10` | root, height, entry count |
| Node | pointer at `+0x00`; u64 array from `+0x08` | parent and keys |
| Node | values at `+0x60`, index stride `0xb8` | 184-byte payload paired with each key |
| Node | u16 at `+0x848`, u16 at `+0x84a`, pointers from `+0x850` | parent edge index, key count, child edges |
| Node bounds | compare post-delete count to `4`; merge/borrow compare to `12` | non-root minimum 5; maximum 11 |
| Replacement | old root call with immediate size `0x8b0` | internal-node storage size for this branch |

The decoded region boundaries fit 11 eight-byte key slots, 11 values of 184 bytes, and 12 eight-byte child slots within the `0x8b0` internal-node size. These independent layout calculations agree with the branch-derived capacity. The key comparison uses unsigned condition codes. The leaf path saves one key and its payload, calls through the `memmove` relocation for subsequent keys and payloads, and decrements the node count. The internal-key path descends first through edge `index`, then repeatedly through the rightmost edge, removes the predecessor leaf entry, and swaps that key and 184-byte value into the repaired cursor position. The original pair is returned from the handle routine. These are static interpretations of the byte and branch witnesses, not observations from running an order.

For human inspection, these excerpts show why the leaf test and merge boundary use different intermediate counts (the generator does not parse disassembler text):

```text
1b17188  movzx r13d, WORD PTR [r12+0x84a]  ; count before deletion
1b172b9  lea   edi, [r13-1]
1b172ca  cmp   di, 0x4
1b172d3  ja    0x1b177cb
1b172ee  movzx esi, WORD PTR [r14+0x848]  ; child index
1b172f6  test  rsi, rsi
1b172fd  je    0x1b176d0                 ; index 0: right sibling
1b1734a  movzx ebp, WORD PTR [rcx+0x84a]  ; left sibling count
1b17351  add   r13d, ebp                 ; old leaf + sibling
1b17354  cmp   r13d, 0xc
1b17358  jae   0x1b17777                 ; borrow if at least 12
```

The principal decision points are listed below; `branches.tsv` records 39 selected conditional branches with their exact opcodes, destinations and fallthroughs. It is a bounded, manually selected branch table, not a claim to have enumerated every branch in the six bodies.

| Condition | Relevant VA | Consequence inferred from the taken/fallthrough paths |
| --- | --- | --- |
| Null root or search exhausts height | `0x2866890`, `0x28668f7` | return first qword `2`; no key deletion on those paths |
| Equal search key | `0x28668e5` | call the handle deletion; then decrement header `+0x10` |
| Found key is in an internal node | `0x1b22ab2`, `0x1b22bb5` | remove predecessor first and replace the internal key/value pair |
| Leaf count after deletion is greater than 4, or leaf has no parent | `0x1b172d3`, `0x1b172df` | skip leaf-level repair |
| Underfull child index is nonzero | `0x1b172fd`, `0x1b17904` | select left sibling; index zero selects right, including at an ancestor |
| Deficient count + sibling count + separator is at most 11 | `0x1b17358`, `0x1b1773b`, `0x1b1795d`, `0x1b179fa` | merge; 12 or more selects borrow |
| Saved deletion cursor exceeds the post-delete leaf length | `0x1b17372`, `0x1b17759` | take the failure path rather than continue the merge |
| Borrow helper context fields differ in zero/nonzero state | `0x1af7492`, `0x1af7497`, `0x1afd194`, `0x1afd19d` | follow an unreachable-code failure path |
| Parent after a merge has at most 4 keys | `0x1b177c0` | continue repair upward; a nonempty root terminates it |
| Internal root becomes empty | `0x1b17d40`, `0x2866a02` | signal wrapper to install old edge 0, decrement height and clear the child's parent |
| Removed payload's first qword is 2 | `0x2866ae7` | return the same first qword sentinel after the deletion and count decrement |

For a leaf that went from 5 to 4 keys, a sibling with 6 yields an 11-key merge, while a sibling with 7 selects borrowing. The left preference is significant: a deficient middle child selects its left neighbor even if its right neighbor could donate. At the leaf, borrow count is one; the ancestor paths calculate `5 - current_count`. The merge and borrow witnesses update moved child parent pointers and their u16 indices. A root that was already a leaf skips repair when its last key is removed; on this path no root-contraction flag is set.

The removed-value sentinel test deserves care. The wrapper compares the full first payload qword with 2 after the key has been removed, and the outer spot context compares the low 32 bits of the returned first word with 2. The caller also takes its low-32-bit equality branch for any returned qword with those low bits even if its high bits differ. The invariant restricting valid payload tags is not established, so neither equality test alone proves that deletion did not occur or that such a tag can occur in a valid value.

Ten diagnostic references are recovered by their RIP-relative operands and explicit lengths in `fatal-assertions.tsv`; duplicate text is retained at both references and embedded newlines are escaped. The branch targets include both borrow destination-capacity and source-underflow failures, a merge-capacity failure, invalid tracked-cursor and slice-length checks, paired-context disagreement, and a zero-height root-replacement failure. The paired-context qwords appear to distinguish leaf and internal levels, but their exact types remain unresolved. The null-root root-replacement branch has a separate indirect call. The tree count has already been decremented before the two root-replacement checks; no general recovery or malformed-memory behavior is inferred from these error paths.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lockfile, Rust compiler/linker flags, two-build comparison and Rust-to-target result: **not yet measured**.

The two wrapper FDEs are each 883 bytes and differ at 18 byte positions. After zeroing only the nine listed four-byte relative operands, both byte strings have SHA-256 `bbbe123041ba59f9f10d2d8027b1e654b16c708c3b79df0bf8cbf27bc5ffc776`. Each masked operand resolves to the same linked VA in both copies. `copy-differences.tsv` preserves all differing bytes and `masked-operands.tsv` records each original instruction, mask position and resolved target. This comparison covers only those two FDE byte strings; it does not match a Rust build or establish whole-ELF equivalence.

`relocations.tsv` records the ELF dynamic relocations for the observed `memcpy` and `memmove` slots and for four other relevant indirect-call slots. `indirect-references.tsv` links 14 selected RIP-relative loads or calls to those slots, including the assertion paths. The latter are `R_X86_64_RELATIVE` records with raw addends; no name or implementation is assumed for their targets. Additional helper call targets, their effects and full relocation closure are not reconstructed. Assertion text bytes are recorded, while other data, vtables and whole-ELF comparison are not covered.

The unittest module contains a separately authored synthetic B-tree model. It checks the 98 combinations of sibling lengths 5 through 11 in both deletion positions, exact merge/borrow boundaries, left-sibling priority, internal predecessor replacement, ancestor borrowing and cascading root contraction. It also tests missing and boundary keys, payload pairing, malformed synthetic trees, invalid ELF addresses and `SHT_NOBITS`, a bad digest, changed FDE start, instruction, value stride and call bytes, changed relocation type, assertion operands, and corruption both inside and outside the declared byte masks. These model scenarios test the consistency of the stated interpretation; they do not execute or emulate node code and are not target-runtime observations.

## Results and limitations

The static export covers 6 selected FDE ranges, 45 fixed byte witnesses, 10 selected direct call edges, 14 indirect references, 39 conditional branch sites, 10 diagnostic references and 6 selected dynamic relocation records. These counts are scopes of this packet, not denominators for node-wide coverage. The 22 focused unittest methods pass without skips. The artifact verification, catalogue check, manifest check and two independently seeded regeneration comparisons are reported separately in the accompanying draft; no node execution or network access was used.

The semantic identity of the value, all valid variants of its first qword, the outer lookup and later cancellation effects are unknown. The test model is not proof of native execution, and the selected branches are not a complete CFG. No project progress gate is requested. Next question: which target-backed value variants can occupy this index, and which subsequent cancellation effects distinguish a missing key from each removed value?
