# RE-001: guarded byte consumption and counter rejection

- Component: unassigned function map; preparatory RE-001 research.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Repository base revision: `05bc2de303c05525b71e7e257426e741bc66a390`. No source mapping or original name is claimed; new research and code are independently authored under the repository's MIT terms.
- Bounded question: what does the entire function at `0x232b1b0` read, update and return when its counter gate and byte cursor are presented with boundary values?
- Claim status: instruction bytes, addresses, effects and control flow are observations; the rule and local variable names below are inferences. Their domain meaning and ownership remain unknown.

For valid, non-overlapping state and result storage, and a readable cursor byte whenever the remaining length is nonzero, let `mode` be the dword at RSI, `limit` the qword at RSI+8, `cursor` the qword at RSI+0x10, `remaining` the qword at RSI+0x18, and `count` the qword at RSI+0x20. If `mode == 1` and `count == UINT64_MAX`, the function writes result tag `2` and leaves the state unchanged. Otherwise, if `mode == 1`, it first increments `count`, then writes tag `2` and returns if the **old** count is at least the unsigned limit. On the remaining paths, a zero remaining length writes result tag `0` and qword `1` at result+8. A nonzero length reads the byte at the cursor, advances the cursor by one, decrements remaining, writes the byte at result+1 and writes tag `0x12`. It returns the result pointer in RAX. Result bytes not specified on a path are left untouched; no error or type names are inferred. In particular, the counter increment survives both a limit rejection and an empty-input result.

## Evidence and instruction walk

The ELF virtual-address window is `0x232b1b0..0x232b209` at file offset `0x232a1b0`; its body SHA-256 is `716eedaeb2a8cd14cdb94de654a1ce0d5fe1dc4462f05071163e7c50b1a062eb`. The FDE at VA/file offset `0xd0092c` references the `zR` CIE at VA/file offset `0xca6ed8`, describes this exact window, and has no LSDA. The following FDE starts at `0x232b210`; the intervening bytes are `cc` padding. FDE metadata alone does not establish a universal function inventory; entry-to-return control flow and padding corroborate this window. Complete unnormalized bytes, each strictly decoded instruction and branch destination, FDE/CIE bytes and section coordinates are retained in `records.json`.

At entry MOV saves the result pointer in RAX. CMP/JNE bypasses the counter for modes other than `1`. For mode `1`, CMP against sign-extended `-1` detects `UINT64_MAX`; the equal branch skips the increment. LEA computes old count + 1 and MOV stores it before CMP/unsigned JAE checks old count against the limit. The zero remaining branch writes the tag and qword described above. Otherwise MOVZX reads a byte, INC and DEC update cursor and length, then the byte and tag are stored. Every branch target is an instruction boundary and every route ends at RET; there are no calls, indirect transfers or callees within the window. Arithmetic on machine registers is modulo 2^64; the stated memory preconditions exclude faults and concurrent mutation. The result and state must be disjoint because stores could otherwise alter subsequent inputs.

Machine-readable counts, enforced against `records.json` by the focused tests:

- Body bytes: 89
- Instructions: 28
- Padding bytes: 7
- Callees: 0
- Direct rel32 hits: 0

The census scans every byte of the complete `.text` range `0x1419300..0x63f0a00` for E8/E9 plus a signed rel32 resolving to this entry. There are no hits, including unaligned opcode-like bytes. This does not find indirect calls, references in data, calls from outside `.text`, or dynamically computed targets; it does not prove the function is unreachable. No callee identities or extents need binding for this leaf. No normalization masks are applied.

## Novelty

Before selecting this entry, these exact searches returned no matches (exit status 1). There are no callees to check for this binding. The slug was also searched before creation.

```sh
rg -i '232b1b0|36876720' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i 'gated.byte.consume' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

## Reproduction and limitations

From the repository root with the authenticated artifact materialized, use Python 3.10+ and its standard library. The tool authenticates the full target before producing files, validates ELF mapping and FDE/CIE, strictly decodes every instruction in the window, verifies branch destinations and padding, and scans all `.text` bytes. The producer copies the packet's fixed prose and verifier and regenerates its semantic record and whitelist manifest. GNU objdump 2.44 and readelf 2.44 were used for independent static discovery; they are not required by the producer, verifier or tests. No captured executable is run and there are no network or chain actions.

```sh
python3 tools/node115_gated_byte_consume.py --out research/work-items/RE-001-node115-gated-byte-consume/
python3 -m unittest tests.test_node115_gated_byte_consume -v
python3 research/work-items/RE-001-node115-gated-byte-consume/verify.py
make verify
make catalogue-check
```

The independently authored model covers the observed rule and target-derived boundary vectors. Controls reject a wrong digest before output, altered body or branch bytes, shifted or resized FDE, and an injected rel32 caller. Since the leaf contains no callees, a wrong-callee-target control is inapplicable; instruction mutation also rejects introducing a call. These checks do not execute the node. Before: the entry was absent from the searched research and PR lists. After: its local normal-return behavior is byte-backed and reproducible. No original source identity, object layout beyond accessed offsets, ABI types, indirect callers, fault behavior, Rust implementation, binary equivalence, component completion or hosted CI is claimed. The result is not a full RE-001 acceptance gate. Next, resolve references to the entry through relocation and data analysis and trace an authenticated caller to identify the surrounding state and result semantics.
