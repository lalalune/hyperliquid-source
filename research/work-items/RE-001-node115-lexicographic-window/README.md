# RE-001: mixed-order comparison and saturated threshold

- Component: unassigned first-party-associated leaf; function mapping for node #115.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No upstream source was copied; the model is independently authored under MIT.
- Bounded question: what does the entire leaf at `0x55ff970` return in AL for readable input memory?

**Answer.** Treat the three dwords at offsets `0x60`, `0x64`, `0x68` as A, and those at `0x4e04`, `0x4e08`, `0x4e0c` as B. Compare their first elements as signed 32-bit integers and the remaining elements as unsigned 32-bit integers, lexicographically. Let C be the unsigned qword at `0x28`, D the unsigned qword at `0x4d98`, and E the unsigned qword at `0x10`. If A is not less than B and C >= D, return 2. Otherwise return 1 if C >= min(2^64-1, E+5000), and 0 otherwise. The result is only AL; upper RAX bits are not claimed.

## Evidence and inference

The ELF VA interval `0x55ff970..0x55ff9d4` corresponds to file offset `0x55fe970`. The body SHA-256 is `4c12e5b827ccfc72a9854dc6ab8218e48651833d2e57df6929619a564ae9e850`. The uniquely selected FDE at VA/file offset `0xf86fa4` describes that interval, uses the zR CIE at VA/file offset `0xca6ed8`, and has no LSDA. The following padding bytes are `cc`, ending at the next indexed FDE entry `0x55ff9e0`. The whole body is decoded in `records.json`, with byte encodings and branch targets. Counts below are read from that record:

- Window bytes: **100**
- Instructions: **28**
- Callees: **0**
- Relative direct-transfer candidates: **4**
- Call-shaped candidates: **4**
- Jump-shaped candidates: **0**
- Padding bytes: **12**

`cmp` followed by `setl`/`jne` tests signed first-word order while preserving comparison flags. When equal, `setb`/`jne` tests unsigned second-word order; if equal, `jae` tests the unsigned third word. The less path goes to the threshold; the other path sets AL to 2 and returns it if C >= D. In the threshold path, subtraction of sign-extended `0xffffec78` adds 5000 modulo 2^64: its unsigned borrow is set exactly when E < 2^64-5000. That path selects the sum directly; the other path performs ADD and uses its carry to select either the sum or all ones. Thus the selected word is saturated E+5000, including E=2^64-5000 where the exact mathematical sum first overflows. `cmp`/`setae` performs the final unsigned threshold comparison. All internal branches land on decoded instruction starts; the last instruction is `ret`, and there are no direct or indirect calls or tail transfers out of this body.

A complete byte-aligned e8/e9 rel32 scan of `.text` (`0x1419300..0x63f0a00`) found the call- and jump-shaped candidates counted above, listed with exact bytes in `records.json`. A byte scan can hit operands or data; these are candidates, not a complete set of proven instruction-boundary callers. It does not find indirect transfers. The call candidate at `0x517beb5` and the LEA at `0x517bd8f` lie in the same FDE `0x517b760..0x517c03d`. The LEA points to Location `0x64768a8`; its relative relocation and metadata identify `l1/src/perp_meta.rs:163:38`. This establishes a source-associated caller, not the leaf’s own source ownership or that the Location and call share a control-flow path. The selected FDE plus full instruction coverage, terminating return and trap-byte gap support this local boundary; they do not establish a global function census.

## Novelty and reproduction

Before selection, the following command returned no matches (exit 1) for the entry address in hex and decimal. There are no behavior-bound callees to check. PR lists were local snapshots, not a live remote query:

```sh
rg -i '55ff970|90175856' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

From the repository root, on Python 3.10+ with the materialized capture, run:

```sh
python3 tools/node115_lexicographic_window.py --out research/work-items/RE-001-node115-lexicographic-window/
python3 -m unittest tests.test_node115_lexicographic_window -v
python3 research/work-items/RE-001-node115-lexicographic-window/verify.py
make verify
make catalogue-check
```

The generator authenticates the full capture before parsing or writing; uses only Python standard library, mmap, and strict narrow instruction decoding; performs no normalization; and does not execute the captured node. Tests exercise rule boundaries and wrong digest, instruction, branch, FDE and direct-call target corruption. `MANIFEST.sha256` covers the packet's exact whitelist; the verifier regenerates the JSON from the authenticated capture. Generator, tests, and verifier do not invoke objdump. No source build or binary comparison exists, so there are no masks or compiled helper closure claims. These checks are static evidence, not target execution.

## Limits and next step

The observation requires readable input at the stated offsets and normal machine execution; object identity, field names, units, original type and business purpose are unknown. The return code meanings, other caller control flow, indirect callers, relocation/data ownership and Rust ABI remain unproved. Source-associated caller context does not prove that this leaf is first-party code. This is not a claim of reconstruction, coverage, correctness of a node subsystem, hosted CI, or a completed component gate. Next, establish the callers' object provenance and what their uses of AL=2 mean before assigning domain semantics.
