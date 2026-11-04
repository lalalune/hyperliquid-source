# RE-021: CALL-family dispatch and alternate account host on node 115

This packet shows how four selected CALL-family opcodes in the node 115 alternate interpreter construct a low-160-bit lookup key and hand off a child action after the alternate host has checked accounts, selected costs and updated the surrounding interpreter state, making those reconstruction decisions possible for an address-09 call under explicit provider and helper assumptions.

- Component ID: `evm`; RE-021 is a bounded continuation of RE-011, not a separate row in the task catalogue.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. The historical, unlicensed reference tree at `999556f6e0a474b8312db96ec3149e1c44e97c23` was used only to locate clues; no implementation was copied.
- Claim status: selected bytes, file offsets, FDE records, relative relocations and branch destinations are observations; opcode names, field roles and the formulas below are inferences from those observations; actual bytecode, live provider selection, mutable memory and full execution remain unresolved.
- Scope included and excluded: the alternate dispatch loop, seven unowned handler extents, their alternate account host, one account loader, one code-preparation helper and one temporary cleanup helper. Ordinary `CALL`, the shared range helper, the existing driver, the frame, the address-09 registry and compression bodies are boundaries already owned by other work. This is not a complete private-fork map, transaction trace, security assessment or component gate.

## Reproduce

From the repository root with the authenticated node #115 artifact present:

```sh
python3 tools/re21_call_host115.py --out research/work-items/RE-021-call-host-115
python3 -m unittest tests.test_re21_call_host115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-021-call-host-115 && sha256sum -c MANIFEST.sha256)
```

For independent regeneration with no programs on `PATH`, substitute an existing writable directory for `<tmp-dir>`:

```sh
python_exec="$(command -v python3)"
PATH= PYTHONHASHSEED=1 TZ=UTC "$python_exec" tools/re21_call_host115.py --out <tmp-dir>/one
PATH= PYTHONHASHSEED=937 TZ=Pacific/Honolulu "$python_exec" tools/re21_call_host115.py --out <tmp-dir>/two
diff -r <tmp-dir>/one <tmp-dir>/two
PATH= "$python_exec" -m unittest tests.test_re21_call_host115
```

An optional independent historical check authenticates the separately supplied #94 artifact, then reads its key, two RELA records and wrapper call. The default command and all tests need only #115. The optional command prints those #94 coordinates and writes exactly the same #115 evidence as the default command.

```sh
python3 tools/re21_call_host115.py --out <tmp-dir>/legacy --legacy references/can1357-hl/bin/hl-node-mainnet-new
git show c5ce58bdc9f346394d5e8ce12e8bd095acaedc6e:research/work-items/RE-021-blake2b-compress-94/README.md
```

Observed environment: Python 3.12.3, Linux x86-64. GNU objdump 2.42 was used only for manual instruction interpretation. The generator and tests use the standard library plus `tools/elf_index.py` and `tools/fde_extents.py`; they do not invoke objdump or any external program. The generator checks the full input SHA-256 before ELF parsing, excludes SHT_NOBITS from file-byte mapping, and rejects unexpected byte windows, branches, symbols and relative relocations. It neither executes the node nor consumes live state. It writes the machine-readable files only; `MANIFEST.sha256` covers all other files in this directory.

## Evidence

Addresses are ELF virtual addresses before load bias; file offsets are from the beginning of the authenticated artifact. `functions.json` records the entire selected FDE bytes, hashes, file offsets, CIE/FDE encodings and exclusive ends. An FDE is an unwind range, not proof of a source-level function boundary or a complete function census. The snippets and direct transfers below are selected observations, not a full CFG.

| Inferred role | Start VA | End VA, exclusive |
| --- | --- | --- |
| Alternate interpreter loop | `0x22d9070` | `0x22d949c` |
| Ordinary DELEGATECALL | `0x2999b00` | `0x2999e6b` |
| Ordinary STATICCALL | `0x2999e70` | `0x299a1c1` |
| Ordinary CALLCODE | `0x299a1d0` | `0x299a579` |
| Alternate DELEGATECALL | `0x299a580` | `0x299a8eb` |
| Alternate CALL | `0x299a8f0` | `0x299ac93` |
| Alternate CALLCODE | `0x299aca0` | `0x299b049` |
| Alternate STATICCALL | `0x299b400` | `0x299b751` |
| Alternate account loader | `0x5463980` | `0x5463f8a` |
| Alternate host | `0x546c330` | `0x546cba0` |
| Code preparation | `0x54793e0` | `0x5479634` |
| Temporary cleanup | `0x563e0e0` | `0x563e100` |

### Dispatch and handoff

The existing alternate driver is a dependency mapped in PR 2104, not a newly selected FDE here. The seven small `prior-boundaries.tsv` excerpts establish the interface needed for this question. At `0x2962fd5` the driver passes the table at `0x6441210` and length `0x800` to a relocated slot whose undefined dynamic symbol is `memcpy`; at `0x2963069` it copies `0x862` bytes from the intermediate buffer to an allocation. It saves that allocation at `0x2963284` and later passes it as the loop's function-table argument, with its +`0x800` address as the price-table argument, before the direct call at `0x296476b`. `dynamic-symbol.json` retains the raw symbol and relocation records. This lineage assumes the ordinary `memcpy` contract, successful allocation, and no intervening alias mutation.

In the loop, `0x22d90d5` loads the instruction pointer, reads one opcode byte, advances the pointer and indexes an eight-byte function slot and a two-byte price. At `0x22d90f3` it subtracts that price from interpreter +`0x188`; carry goes to the raw `0x20` status path, while the no-carry arm calls the selected function at `0x22d9106`. The subtraction writes its fixed-width result before the carry branch. The subsequent status handler, periodic-counter branch and other opcode classes have additional paths; the evidence does not assert that an underflow invariably terminates the whole driver.

For the success publication described below, the loop copies the action and status bytes into its output, and the driver tests the output byte at +`0x58`, then reads and forwards the first two output words on its selected zero branch. PR 2104 separately maps the later driver-to-alternate-frame call and the frame-to-provider route. Composition across those boundaries assumes the selected normal branches, unmodified copied pointers and successful external helpers.

`opcode-table.tsv` reads the actual `R_X86_64_RELATIVE` addends for the selected entries. The following labels distinguish two tables in this artifact; they do not identify a live chain fork.

| Opcode | Ordinary entry | Alternate entry | Initial stack words | Frame scheme |
| --- | --- | --- | ---: | ---: |
| `f1` CALL | prior work | `0x299a8f0` | 3 | 0 |
| `f2` CALLCODE | `0x299a1d0` | `0x299aca0` | 3 | 1 |
| `f4` DELEGATECALL | `0x2999b00` | `0x299a580` | 2 | 2 |
| `fa` STATICCALL | `0x2999e70` | `0x299b400` | 2 | 3 |

The ordinary `f1` implementation and shared range helper are already covered by PR 2168 and are not selected here. Each other same-opcode pair has equal FDE byte length and 24 differing byte positions. `paired-bodies.json` checks 12 specific four-byte PC-relative operand fields per pair: 11 resolve to the same destination, and the remaining indirect call resolves to ordinary host slot `0x64e6e00` or alternate host slot `0x64e6e08`. The respective RELA addends are `0x4335cf0` and `0x546c330`. All bytes outside those 48 explicitly listed operand positions match. This is a within-#115 comparison; it is not a source rebuild, complete relocation normalization or proof of source equivalence.

### Handler inputs, publication and errors

The handlers consume the initial words in the table before calling the previously studied range helper at `0x29998f0`; that helper owns the remaining range/memory checks. The 256-bit requested-gas word is reduced to its low 64 bits when the upper limbs are zero and otherwise to `2^64 - 1`. After the range helper's normal result, the byte swaps and stores form a 20-byte key from the low 160 bits of the target word, both for the host argument and at frame +`0x90`. `key-lanes.tsv` and `target-cases.tsv` state the inferred byte projection; their sample inputs are synthetic. For instance, both the word 9 and a word with bit 160 set plus 9 project to 19 zero bytes followed by `09`; 8 and 10 do not.

On the selected normal arm the handler prepares `0xd0` bytes and publishes a pointer as an action: interpreter +`0xb8` becomes 1, +`0xc0` receives the allocated pointer, +`0x110` becomes 0, +`0x149` becomes 0, and the handler returns raw byte `0x04`. Existing action contents have separate conditional cleanup branches before replacement. The `f1` handler passes host mode 1; the selected `f2`, `f4` and `fa` handlers pass host mode 0. The frame's scheme byte is at +`0xce`. `f4` writes a value tag of 1 and copies the current interpreter's value-shaped 32 bytes; `f1` and `f2` write tag 0 with their supplied value, and `fa` clears that value area and writes static flag 1. The other observed static flag comes from interpreter +`0x1a8`. Exact stores and their per-handler coordinates are in `frame-modes.tsv`.

`handler-gates.tsv` records these control points separately for all seven handlers:

| Condition | Selected consequence |
| --- | --- |
| Initial stack length below the table's minimum | Return raw `0x2c` before the range helper. |
| `f4` revision byte +`0x1a9` equals 0 | Return raw `0x2b`. |
| `fa` revision byte +`0x1a9` is at most 3 | Return raw `0x2b`. |
| `f1` nonzero value and bit 0 of +`0x1a8` is set | Return raw `0x27` after the first three words are consumed. |
| Range helper reports its error form | Propagate its returned byte; the helper body is a boundary. |
| Child-frame allocation is null | Branch to a separate allocation-failure helper, rather than publishing the action. |
| Alternate host returns discriminator 2 | Propagate the host's error byte instead of constructing the child action. |

These raw values are not assigned source-level error names. Helper side effects, all prior-action destructors and allocator internals remain outside the selected analysis.

### Account classification, costs and state writes

The alternate host's first account request at `0x546c3f5` uses relative slot `0x64e6ce8` with addend `0x5463980`; the optional second request at `0x546c653` uses the same slot. The loader calls an external lookup, can consult the external policy slot `0x64ea6d8`, and on a miss can call a backend before insertion. For canonical Boolean guard and policy results, `loader-policy-cases.tsv` records that guard 1 and policy 0 reject with discriminator 2. A successful miss appends a tag-0, 20-byte-key record at stride `0x58` when policy is 0; a stale cached entry's accepted refresh clears flag `0x10`, conditionally performs the `0x40` cleanup, clears `0x80`, and appends the corresponding tag-0 record. A matching epoch and clear `0x10` use a cached-result arm. Growth, backend behavior, concurrent aliases and non-Boolean policy returns are not modeled.

Code preparation returns immediately for a nonzero account +`0x70`. Otherwise it compares account +`0x48` through +`0x67` against the 32-byte literal in `constants.json`, selects a default or map-backed object, increments a reference, and installs the resulting pointer at +`0x70`, conditionally releasing the old pointer. Allocation, external map and exception behavior remain boundaries.

Both the primary and optional secondary account then pass through the byte-checked classification windows at `0x546c42f` and `0x546c720`. The context byte at +`0x396` is the mode `M`, independent of interpreter revision byte `R`. For 32-byte fields `H` at account +`0x48` and `W` at +`0x28`, 64-bit field `N` at +`0x68`, and byte `F` at +`0x8c`, the inferred Boolean is:

```text
M <= 2:   (F & 0x08 != 0) and (F & 0x04 == 0)
M > 2:    (H is all zero or equals the recorded literal) and W is all zero and N == 0
```

`classification-pair.json` checks the two RIP-relative literal targets and one differing register byte, then compares the other bytes in these 145-byte windows. Its nine masked positions are confined to that within-target comparison. `classification-cases.tsv` contains synthetic controls, not account snapshots; names for these fields and the live mode remain unresolved.

On the selected primary branch, let `G` be gas after any initial value debit, `C` schedule +`0x80`, `E` schedule +`0x88`, and `K` the loader's non-error result byte. The loader guard is `R >= 7 and G < C`. The first cost is `C` only when `R >= 7` and bit 0 of `K` is set. When host mode is 1 and the classifier is true, an additional `E` is selected if `R < 3` or the supplied value is nonzero; addition carry takes a separate failure helper. The model in `primary-cost-cases.tsv` excludes a later optional secondary-account cost.

If the selected code object is non-null, has byte +`0x7c` equal to 1, and its length at +`0x40` exceeds 22, the host takes 20 bytes from its data pointer +3 and can perform a second account request. For this arm, let `A` be the first cost and `X` schedule +`0x90`: it checks `A + X`, requires that sum not exceed `G`, then checks adding `C` before computing the second loader guard. A non-error second result selects `A + X + C` if its low bit is set, else `A + X`. The two overflow destinations, insufficient-gas cleanup and second-loader failure are distinct. The second key comes from code data and is not assumed to equal the frame's address-09 key. `secondary-cost-cases.tsv` models only these checked operations; later cost charging may still fail.

On the selected host-mode-1, classified-account branch, `0x546c69e` first sets adjustment `B` to zero. If the supplied value is nonzero and context byte +`0x265` is nonzero, it instead loads `B` from schedule +`0x158`. The value selector comes from the initial host argument and is restored on both selected code-object arms. `adjustment-cases.tsv` covers zero and nonzero context bytes and the coefficient boundary. Other inspected paths explicitly clear `B` at `0x546c893` or `0x546c9db`; those examples do not close every possible exceptional or helper path.

After a successful access-cost subtraction, the host compares another unsigned interpreter field at +`0x190` with `B`. If that field is at least `B`, it stores the difference; otherwise it subtracts the deficit from gas and stores zero, with a separate failure branch if the deficit is unaffordable. On a successful adjustment it updates +`0x198` by signed saturating addition of the bit pattern of `B`. A failed deficit check leaves those latter two fields unchanged, but the preceding successful access charge has already been stored. `accounting-cases.tsv` covers equality, failure and both signed saturation limits.

For revision greater than 1, the selected forwarding path caps requested gas at `remaining - remaining // divisor` using schedule +`0x70`; a zero divisor takes a separate failure helper. It subtracts the forwarded amount, then, for nonzero value, adds schedule +`0xc0` to the child amount with unsigned saturation. The byte sequence uses either a 32-bit or a 64-bit division according to operand width. `gas-cases.tsv` is a restricted synthetic model with no additional accounting deficit or secondary-key charge; it does not purport to run the target.

### Exceptional exits and address-09 dependency

The LSDA decoder retains the raw call-site records and action indices, without decoding action chains or claiming all cleanup is understood. For example, the selected alternate host call at `0x546c71b` lies in an encoded range landing at `0x546cb6f`; the selected landing sequence decrements a reference, may call its release slot, calls `0x563e0e0` on a temporary and reaches the unwind-resume boundary. The alternate DELEGATECALL publication range from `0x299a800` through `0x299a855` has landing `0x299a8a8`. These are encoded exception associations, not observations of an exception in a live process.

The authenticated #115 ordinary address-09 key is at VA `0x64c0750` (file offset `0x64be750`), with callback slot `0x64c0748` relocated to `0x5c165b0`. The separate scaled key is at VA `0x6492ff8` (file offset `0x6490ff8`), with callback slot `0x6493010` relocated to `0x5c16650` and divisor 10. The projected frame key can therefore equal either record's key. PR 2104 maps the conditional alternate frame and scaled selector; PR 2049 maps the ordinary runtime lookup, wrapper and compression candidates. Their provider initialization, callback and rollback bodies are dependencies, not reanalyzed here. A matching key alone does not prove a live lookup hit or callback execution.

The #94 clue belongs to the distinct SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. The optional authenticated #94 check reads its key at VA `0x574f0c0` (file offset `0x574d0c0`), callback slot `0x574f0b0` to `0x4e9d2a0`, and the wrapper call at `0x4e9d3bd` through slot `0x5776f28` to candidate `0x4e9a8a0`. The independently extracted #115 records above cross-check the address-09 identity only; neither #94 coordinates nor its compressor implementation are transplanted, and no cross-release body equivalence is claimed.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependency closure, compiler/linker settings, two-build comparison, source-to-target byte matching, complete helper/data/relocation closure and whole-ELF equivalence: **not yet implemented or measured**. The two explicit comparison masks above are strictly within the authenticated target and do not mask a reconstructed binary.

The focused suite has 47 passing tests and zero skips. Controls include a wrong full digest; NOBITS, ambiguous, truncated and cross-boundary reads; altered instruction windows, branch displacements, frame schemes, classifier bytes and paired-body operands; missing, duplicate or wrong-type relocations; malformed dynamic symbols and LSDA records; all 256 individual stack-word bits; revision and stack gates; gas, policy, classification, secondary-cost, adjustment-selection and signed-saturation boundaries. Fresh generation is checked byte for byte against every saved machine-readable evidence file. The finite models are independently specified from the pinned byte sequences and do not execute captured code.

## Results and limitations

`summary.json` records 12 selected FDE extents containing 11,655 bytes, seven selected opcode entries and handler rows, three paired-body comparisons, 80 fixed byte windows, 77 direct transfers, seven prior-boundary excerpts, 12 selected indirect transfers, 14 relative and one symbol relocation, and 11 LSDA headers with 84 encoded call sites. It also records the counts of synthetic cases. These selected denominators are not total function coverage, complete branch coverage, matched source windows or component completion.

The `evm` component remains 0/4. Its first task asks for the broader private-fork boundaries and state-transition inputs; this conditional path does not complete that task. In particular, full configuration selection, actual live opcode tables and provider membership, all meanings and origins of host accounting fields, optional-code aliases, general backend effects, complete helper and unwind closure, captured execution, complete BLAKE2b compression and an independently validated Rust reconstruction remain open. No progress gate or generated catalogue is changed.

Next question: bind context byte +`0x265` and the schedule coefficients to a separately authenticated fork configuration, then close the remaining host and callback exception paths for that configuration.
