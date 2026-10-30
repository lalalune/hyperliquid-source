# Result: node #94 spot clearinghouse inventory

**Verdict: strong for this bounded static inventory.** Diagnostic yield is limited:
only **one of 12 reference diagnostics** binds under the required Location/FDE rule.
The packet's depth comes from exact relocation and FDE records, instruction-boundary
checks, explicit literal lengths, seven same-call panic Location associations,
three scoped rel32 edges, retained negative results and corruption controls.
It does not recover spot-clearinghouse behavior or earn a component gate.

Target: `artifacts/node/94/hl-node`, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All observations below refer to that digest. Coordinates are ELF virtual addresses;
FDE ends are exclusive. Machine-readable evidence is in [inventory.json](inventory.json)
and complete scoped instruction transcripts are in [disassembly.json](disassembly.json).

## Observed Location census

| Basename under `l1/src/spot_clearinghouse/` | Records | LEAs | Distinct owning FDEs |
| --- | ---: | ---: | ---: |
| cl_trait.rs | 12 | 15 | 7 |
| impl_outcome.rs | 3 | 4 | 3 |
| spot_clearinghouse.rs | 1 | 1 | 1 |
| types.rs | 1 | 7 | 7 |
| Union | **17** | **27** | **15** |

The basename FDE counts overlap. There are **16 distinct path/line/column tuples**:
`impl_outcome.rs:155:14` has two separate relocated records, at `0x56bd7f8` and
`0x571fd48`; both are retained. There are no unowned scoped LEA candidates.
These are all records accepted by the explicit relocation/layout/LEA method in
README.md, not all possible source Locations or all functions in the component.

| FDE start | FDE end | Scoped LEAs | Scoped source coordinates (basename:line:column) |
| --- | --- | ---: | --- |
| `0x271a1d0` | `0x271b16d` | 1 | impl_outcome.rs:155:14 |
| `0x3308ab0` | `0x3308d74` | 1 | spot_clearinghouse.rs:846:98 |
| `0x37198a0` | `0x371a970` | 2 | impl_outcome.rs:547:42 |
| `0x371d120` | `0x371d621` | 1 | types.rs:123:50 |
| `0x3720200` | `0x3720a62` | 1 | types.rs:123:50 |
| `0x3721780` | `0x3721c10` | 1 | types.rs:123:50 |
| `0x3723010` | `0x3723056` | 1 | types.rs:123:50 |
| `0x372b9d0` | `0x372d5de` | 5 | types.rs:123:50; cl_trait.rs:339:75, 347:30, 359:18, 363:14 |
| `0x372e0a0` | `0x372ee5b` | 2 | types.rs:123:50; cl_trait.rs:692:14 |
| `0x3c018a0` | `0x3c01be3` | 6 | cl_trait.rs:898:73, 953:61, 961:63, 973:63, 981:63, 989:73 |
| `0x445d4a0` | `0x445da71` | 2 | types.rs:123:50; impl_outcome.rs:155:14 |
| `0x445e270` | `0x445e621` | 1 | cl_trait.rs:621:28 |
| `0x445e630` | `0x445e9e1` | 1 | cl_trait.rs:621:28 |
| `0x445e9f0` | `0x445eda1` | 1 | cl_trait.rs:621:28 |
| `0x445edb0` | `0x445f161` | 1 | cl_trait.rs:621:28 |

The complete Location-to-LEA-to-FDE mapping is in `location_leas`, with instruction
bytes, file offsets and destination registers. The total **30,475 FDE bytes** are
unwind-described ranges; this is not a function-coverage or matched-body denominator.

## Diagnostics: observed bindings and honest negatives

**2 bound / 12 unresolved over 14 probes**. The denominator comprises 12 reference
literal prefixes, one requested balance phrase, and one observed generic runtime
message. The generic message is explicitly separate from the single spot-specific
positive. There is no binding of a spot send/transfer operation or outcome error code.

The spot-specific positive is the 56-byte prefix:

```text
error while computing existing token balances total_wei=
```

At `0x3308cd3`, bytes `48 8d 35 57 c9 ee fc` decode as a LEA into RSI of
`0x1f5631`, inside FDE `[0x3308ab0,0x3308d74)`. At that anchor the byte `38`
(hex, decimal 56) is followed by exactly those 56 ASCII bytes, then `c0`.
The text begins at `0x1f5632`; the LEA addresses the counted descriptor prefix,
not the first ASCII byte. This is **not** a conventional ptr+len pair and no
formatter bytecode semantics are claimed. The same FDE loads the relocated
Location at `0x56e8ac8`, `spot_clearinghouse.rs:846:98`, through LEA `0x3308d41`.
The next instruction calls through slot `0x576e470`; the Location bytes are
`00000000000000004c000000000000004e03000062000000`, and its path relocation
addend is `0x1fb334`. Full argument construction and surrounding instructions are
retained, including the indirect formatter call at `0x3308ce4`.

The generic 43-byte text ``called `Result::unwrap()` on an `Err` value`` has
**eight RDI-pointer / ESI-length / indirect-call anchors** in three scoped FDEs.
Five are in `0x3c018a0`, two in `0x372b9d0`, and one in `0x271a1d0`.
Seven also put a scoped Location into R8 in that exact contiguous setup. For example:

| Instruction VA | Bytes | Decoded observation |
| --- | --- | --- |
| `0x3c01a8f` | `48 8d 3d cc 7d 9b fc` | RDI = literal `0x5b9862` |
| `0x3c01a96` | `48 8d 0d b3 34 b1 01` | RCX = `0x5714f50` (data role unresolved) |
| `0x3c01a9d` | `4c 8d 05 e4 31 b1 01` | R8 = Location `0x5714c88`, cl_trait.rs:953:61 |
| `0x3c01aa4` | `48 8d 54 24 38` | RDX = stack address |
| `0x3c01aa9` | `be 2b 00 00 00` | ESI = 43 |
| `0x3c01aae` | `ff 15 94 c5 b6 01` | call through `0x576e048`, RELATIVE addend `0x157aa10` |

The generator rejects intervening control flow, pointer clobbers, wrong lengths
and different call forms. Register argument interpretation is consistent with
SysV x86-64; no runtime execution is inferred. The eighth anchor has only FDE
co-location with a scoped Location: its same-call Location is outside the path
rule, so it gets no same-call spot association. The 1,631 generic unscoped LEA
candidates are counted as omitted, not promoted to component evidence.

| Unresolved probe(s) | What was actually found |
| --- | --- |
| `spot index in bounds`, `spot balance hold overflow`, `spot token conversion succeeds`, `spot book index in bounds`, `spot balance underflow`, `spot wei addition overflow` | No exact `.rodata` occurrence. Reference panic wording is not target evidence. |
| `BUG: distributing to existing token final_allocation_check overflow` | No exact `.rodata` occurrence. |
| `total balance of token is zero` | Bytes at `0x5992e3`; no accepted scoped length-bearing LEA. |
| `no user has wei after distributing` | Bytes at `0x599301`; no accepted scoped length-bearing LEA. |
| `could not distribute remainder=` | Counted-prefix candidate LEA `0x3722b9d` belongs to FDE `0x37227a0`, which has no scoped Location LEA. Excluded. |
| `BUG: distributing to existing token final_allocation_check=` | Counted-prefix candidate LEA `0x3722c9a` belongs to that same unscoped FDE. Excluded. |
| `insufficient balance` | Substring at `0x59e118` in longer text; no accepted scoped length-bearing LEA. It does not identify a spot balance error. |

The out-of-scope LEAs are retained as negative byte candidates; they were not given
full boundary validation or function names. A missing anchor is not proof that a
feature, error path or source expression is absent from node #94.

## Constants

**1 numeric binding / 1 unresolved lead**, a deliberately limited two-value survey.
Binary64 **1.01** has one `.rodata` occurrence, `0x20a528`, bytes
`29 5c 8f c2 f5 28 f0 3f`. Seven decoded RIP `movsd` operands in four scoped FDEs
address exactly it: sites `0x3308aee`, `0x372cd69`, `0x372cde5`, `0x372e84e`,
`0x372e8ca`, `0x445d6be`, `0x445d7e9`. This establishes a numeric operand
co-located with the scoped code. It does not prove exclusive component ownership,
`MAX_PROPORTIONAL_FACTOR`, `MAX_DEPLOYER_SHARE_FACTOR`, or a financial rule.

Binary64 **100000.0** has **11** `.rodata` occurrences. Six scoped `divsd` operands
address `0x20a9e8`; those raw operands are retained, but the lead
`DEPLOYER_SHARE_DENOMINATOR` remains unresolved under the conservative unique-value
rule. Small status numbers, sentinel addresses, decimals and scaling constants
are not counted or claimed.

## Static call edges

All three E8 calls begin on decoded boundaries and land at another scoped FDE's
exact start. The destination is computed from **next instruction + signed disp32**.

| Caller FDE | Call site | Raw bytes | Signed displacement | Destination FDE |
| --- | --- | --- | ---: | --- |
| `0x3721780` | `0x3721beb` | `e8 30 b5 ff ff` | -19152 | `0x371d120` |
| `0x372b9d0` | `0x372c196` | `e8 05 57 4d 00` | 5068549 | `0x3c018a0` |
| `0x372e0a0` | `0x372e392` | `e8 09 35 4d 00` | 5059849 | `0x3c018a0` |

Both ends of the first edge independently load `types.rs:123:50`. The last two
callers have cl_trait.rs and types.rs anchors; their shared callee has the six
cl_trait.rs Locations listed above. This is useful topology without assigning
unproven Rust function names. Reachability from a node entrypoint is not proved.

## Inferences, non-claims and next question

The error prefix makes FDE `0x3308ab0` a useful candidate for existing-token balance
aggregation research. The two callers of `0x3c018a0` suggest shared cl_trait logic.
These are research directions, **not recovered names or established semantics**.
Target Location line numbers refer to embedded original paths, not line numbers
in the inferred can1357 files.

Explicit non-claims:

- No captured node/visor execution, live traffic, behavior comparison or side-effect observation.
- No implementation, Cargo workspace/build, original-source recovery or binary equivalence.
- No perp clearinghouse, margin, oracle, liquidation, RE-004 decimal admission or wei-scale claims.
- No balance transfer/send rules, error discriminants, settlement arithmetic, rounding, overflow policy, state layouts or fee semantics.
- No exhaustive diagnostic/constant census beyond the stated probes; no complete formatter grammar or formatted output.
- No proof that a shared FDE belongs exclusively to spot clearinghouse; Locations can be inlined or propagated.
- No complete CFG, function boundary census, runtime reachability or function naming. FDE extents describe unwind metadata.
- No helper closure, indirect-call graph, tail-call census, vtable/data closure or whole-ELF relocation identity.
- No normalized/raw matched-window denominator, reconstructed Rust comparison, full-node build or whole-ELF equality.
- No node #115 or visor claim, hosted CI/container success, progress credit or gate change.

Next bounded question: validate the input dataflow and error construction around
`0x3308ab0` and its `0x3308ce4` formatter call, while preserving this packet's
unresolved formatter and argument semantics. That would add behavior evidence;
the present inventory cannot supply it by itself.

## Validation

| Command | Actual result |
| --- | --- |
| `make doctor` | PASS; analysis ready, exact rebuild not ready |
| Generator with the requested `--out` directory | PASS; the metrics above were reproduced |
| `python3 -m unittest tests.test_spot_clearinghouse_inventory -v` | PASS, **30 tests**, 9.554 s |
| Packet `verify.py` | PASS; whitelist, hashes, target digest, byte-identical regeneration and pinned facts |
| Packet `verify.py` under `python3 -O -B` | PASS; checks do not depend on assertions |
| Hash-seed regeneration under `PYTHONHASHSEED=0/97`, Python `-O -B` | PASS; both JSON files byte-identical |
| `make test` | PASS, **461 tests**, 190.126 s, no skips |
| `make catalogue-check` | PASS; catalogue/progress tables match pinned inputs |
| `make verify` | PASS; artifact hashes, signatures, pinned upstream pairs and 37 imported files verified |
| `make reproduce` | PASS; inventories and refined classifications reproduce the imported evidence |

No hosted CI, container build or Rust build was run. No progress/gate/catalogue
change was made. Full repository provenance verification remains a maintainer
checkout prerequisite, separate from the digest-bound packet result.
