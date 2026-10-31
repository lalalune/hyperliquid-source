# RE-014: how the execute-action enum and dispatcher change from node #94 to node #115

- **Component ID:** `action-dispatch` (task RE-014, release drift). The path qualification also touches
  `action-wire` (`l1/action/*`) and `exchange` (`l1/exchange/impl_outcome_deploy.rs`).
- **Target release and full SHA-256:** primary target node #94, `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. Comparison target node #115,
  `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
  Every #115 address and constant here was derived from the #115 bytes. None was copied from #94.
- **Source commit / reference commit:** repository `main` at `1f8c67c63ca4794c9689235471c60297f8a5c985`.
  The can1357 reference (`999556f6e0a474b8312db96ec3149e1c44e97c23`) is used only through the merged RE-010
  packet JSON (`research/work-items/RE-010-exchange-handlers/exchange-dispatch.json`, sha256
  `bf82df7744abc508bd73bc8337d5b21af0a17eab9c64b6849137a4f58dfa5cb1`, pinned in the tool). This packet
  neither reads nor copies the reference tree.
- **Claim status:** observation for the tables, idioms, jump tables, arm paths, stored strings, call
  references and Location ownership. Two results rest on inferences and are marked where they are used:
  - which serde name an *execute* arm handles is inference **I2** (the serializer arms bind tag index to name
    in bytes; the execute dispatchers are tied to that only by the shared idiom and 4 Location anchors);
  - reading the [rsp+0x10] / [rsp+0x18] string as the Rust variant identifier is inference **I1**.
  Open items are listed under Unknowns.
- **What is new here, and what is not.** New: the per-variant drift from #94 to #115 (the name join, the
  per-variant `[r12]` arms and handlers of both releases per I2, the #115-only `[r15]` family and the
  qualification of four catalogue paths), supported by the serializer byte binding (O3) and the Location
  anchors (O8). Not new: for #94, the three `VARIANTS` copies, the names of RE-010 cases 76-87 with their
  arms, first calls and first-call FDE extents, and the 51/76 `wire_type` agreement all agree with open PR
  #226 (head `ad161cb7dde4e9e6246f831e5fba4c90c8600dee`,
  `research/work-items/RE-010-dispatch-cases-76-87/README.md`), which reported them first (see Relation to
  other work).
- **Scope included:** all three copies per release of the serde `VARIANTS` table; every occurrence of each
  release's consecutive 64-bit tag-to-index idiom, with either cmov (`cmovae` or `cmovb`) and in any
  register allocation (Method 3), and the jump table its result indexes (directly or after a short gap); a
  list of the same bias and cmov whose default register is loaded elsewhere; the serializers; both
  dispatcher families that put the same `mov ebp,0x3b9aca00` sentinel before the idiom (`[r12]`: 3 per
  release; `[r15]`: 3 in #115, 0 in #94), each arm to its first call; a name-keyed join; Location anchors and
  the direct callers of their owners; qualification of four catalogue paths; a re-derivation of RE-010; two
  census controls over all of `.text`.
- **Scope excluded:** handler semantics, payload layouts, deserializer code, the roles of the 41 (#94) and 45
  (#115) idiom-site jump tables classed `other` and of the 4 / 6 idiom sites without a table, the default
  value and tables of the 10 / 14 listed sites whose default register is loaded elsewhere, the 32-bit
  byte-truncated variant of the idiom, index computations without a cmov (Method 3), what the
  `[r15]`-family handlers do, cross-release code equivalence, the visor and every gate in
  `research/progress.json`.

## Question

How does the execute-action enum and its dispatcher change between #94 and #115? For every #94 variant,
give its serde name, serde index, jump-table arm and first-call handler, and its #115 counterpart. Classify
each variant as kept at the same index, kept but shifted, removed, or added. Then use the handlers to decide
whether each of four action-related catalogue drift paths is changed or added code, or only a missing or
added diagnostic path. The four paths are `absent115` `l1/action/c_deposit.rs` and `l1/action/evm_raw_tx.rs`,
and `added115` `l1/action/user_outcome.rs` and `l1/exchange/impl_outcome_deploy.rs`.

## Reproduce

From the repository root, on Darwin 25.6.0 (arm64) with Python 3.13.18 (stdlib only). GNU
objdump/readelf 2.47.20260726 is used only for the cross-check tests and the excerpts. Inputs are the two
binaries and the RE-010 JSON. Nothing is executed and no network is used. The run takes about 4 s.

    python3 -B tools/action_dispatch_drift.py --out research/work-items/RE-014-action-dispatch-drift/action-dispatch-drift.json
    python3 -I -B research/work-items/RE-014-action-dispatch-drift/verify.py
    python3 -O -B research/work-items/RE-014-action-dispatch-drift/verify.py
    python3 -B -m unittest tests.test_action_dispatch_drift -v

The tool writes sorted JSON with indent 1 and addresses as hex strings. Its output is byte-identical for
`PYTHONHASHSEED` 0, 7 and 99 (the test runs all three) and under `-OO`, and the test pins its sha256. The
CLI options are `--binary` (#94), `--binary-115` and `--out`. The tool checks each input's digest (#94,
#115, RE-010 JSON) before it parses that input, and it exits with status 2 on any pinned-shape mismatch,
malformed input or unreadable file. `objdump-excerpts.txt` holds 105 GNU objdump or readelf windows for
representative cited sites, each with its exact command: code windows, the cited RELATIVE relocations,
strings and Location records, and the `readelf -wf` lines of the cited dispatchers, serializers, handlers
and owners. It does not show every cited site. The Binutils tests check the other cited code sites, every
idiom and default-elsewhere site, every dispatcher reference and every owner caller against an objdump
linear sweep from the containing FDE start, every RELATIVE relocation against `readelf -rW`, and the FDE
bounds of dispatchers, serializers and arm handlers against `readelf -wf`.

**Coordinate system.** Addresses are ELF virtual addresses as linked. Both images are PIE with base 0, so
file offset = VA − p_vaddr + p_offset of the containing PT_LOAD. Code addresses are instruction starts,
REX prefix included. In #94, `.text` VA 0x1343c80 is at file offset 0x1342c80. In #115 it is VA 0x1419300
at offset 0x1418300.

## Method

1. **Readers.** FDE bounds come from `.eh_frame_hdr`, RELATIVE relocations from `.rela.dyn`, and RIP-lea
   targets from a byte scan of `.text`, all through `tools/state_roots.py`. Arm walking uses RE-010's strict
   `tools/exchange_dispatch.walk`. Both modules are loaded with importlib and their files are not modified.
   A second, private instance of `exchange_dispatch` runs RE-010's own `walk` with `decode_one` wrapped to
   accept exactly three more encodings (`cmp eax/rax,imm32` `3d`, `xor r/m,r` `31`, `cmovcc` `0f 4x`). It is
   used only for an execute arm the strict walker rejects, never for a primary instance, and every arm it
   decodes is marked `extended_decoder` in the JSON.
2. **VARIANTS.** The seed is the exact string `batchModify` in `.rodata`. The tool takes every RELATIVE slot
   in `.data.rel.ro` that points at the seed and has length 11. From each one it walks back to the nearest
   lea-referenced slot, which is the array start. It walks forward to the slot whose string matches
   `variant index 0 <= i < N` exactly. Every slot in between must be a relocated ASCII identifier, and no
   slot strictly inside may be lea-referenced. N must equal the run length. All copies must be identical.
3. **Tag-to-index idiom.** The bias and the default index are pinned per release from that release's own
   bytes; the registers and the cmov polarity are free:
   - #94: `lea X,[R-0x74]; cmp R,0x74; mov D32,0x14`, then `cmovae D,X` (index D) or `cmovb X,D` (index X),
     with X ≠ R and D ≠ X;
   - #115: `sub R,0x86; mov D32,0x14`, then `cmovae D,R` (index D) or `cmovb R,D` (index R), with D ≠ R.

   R is the tag register; the cmov destination is the table index register I, and both polarities give
   I = tag − bias when tag ≥ bias, else 0x14. The instructions must be consecutive and in this order, with
   64-bit (REX.W) `lea`, `cmp`, `sub` and register-form `cmovae`/`cmovb`, and `mov r32,imm32` (`B8+r`) for
   the default. The dispatchers use one allocation, which is also the pinned byte form of the profile
   (`bias_block`): #94 R = D = I = `rax`, X = `rcx`; #115 R = `rax`, D = I = `rcx`. The first version of this
   survey matched only that byte form, the second any allocation of `cmovae` only.
   - **Listed, not surveyed** (`idiom_default_elsewhere`): the bias computation directly followed by the
     cmov, with no default load in between (#94 `lea X,[R-0x74]; cmp R,0x74; cmovb X,D` or `cmovae D,X`;
     #115 `sub R,0x86; cmovb R,D` or `cmovae D,R`; D ≠ R and D ≠ X). These bytes do not show the value of D,
     so the tool assigns no table, shape or role.
   - **Not matched:** a 32-bit, byte-truncated variant (`lea e?x,[R-0x74]` or `lea e?x,[R+0x7a]`,
     `cmp R,bias`, `movzx`, `mov e?x,0x14`, `cmovae e?x,e?x`). In #115 the entries of the `[r15]`
     dispatchers and of execute instance 0 use it for the gate byte (O6/O7). Index computations without a
     cmov (for example with a branch) were not searched.

   An objdump control (Negative controls) looks for a cmovcc of any condition next to a `mov r32,0x14` or a
   bias instruction on a 32- or 64-bit register. Apart from the surveyed and listed sites it finds only the
   byte-truncated variant, at 1 (#94) and 8 (#115) sites, and one unrelated #115 equality test.

   The tool lists every occurrence in `.text` and looks for `lea B,[rip+T]; movsxd J,[B+I*4]; add J,B;
   jmp J` with T in `.rodata` and any B and J; at most two `mov [rsp+d8],r64` stores may sit before the
   `jmp`. Between the idiom and the `lea` it allows at most 4 gap instructions: `mov r/m,r` in register form,
   `mov r,imm`, `xor r,r` (one register), `mov r64,[rsp+disp]` and `lea r64,[base+disp]` (no index, not
   RIP-relative) that do not write I, plus `dec I` and at most one bounds check `cmp I,imm8` directly
   followed by `ja`. A table read takes N entries, or imm8 + 1 after a bounds check. Shapes: `direct`,
   `direct_with_stores`, `after_gap`, `after_bounds_check`, or `no_table`.
4. **Roles.** Only tables with N in-FDE, pairwise-distinct entries and no bounds check get a role.
   - `serializer`: there is one stack offset at which arm K's straight-line path stores the &str VARIANTS[K]
     (exact, case-sensitive) for every K, as a (ptr, len) pair with the pointer from a RIP lea and the length
     from an imm32 store. The type, variant and tag strings sit 0x30, 0x20 and 0x10 below it.
   - `execute`: directly before the idiom stand `mov ebp,0x3b9aca00; mov R,[r12]`, with R the idiom's tag
     register (RE-010's dispatcher shape). Exactly 3 such sites must exist in each release.
   - `sentinel_other_base`: the same sentinel and tag load with another base register. The pinned count is
     0 in #94 and 3 in #115. Any sentinel site without an N-way table fails closed.
   - `other`: listed, not analysed.
5. **Arms.** Each arm is walked to its first call or jmp. Entry branches are walked one level, as RE-010
   does. A jmp that lands inside another arm's straight-line path is resolved as that arm's shared tail.
   The tool re-walks from the jump target and requires the same terminator (a consistency assertion that a
   linear decoder cannot fail). Any other jmp has no handler. The primary instance (lowest address) of each
   family must decode with the strict walker alone.
6. **Locations.** A Location record is a RELATIVE slot in `.data.rel.ro` whose addend is in `.rodata`,
   followed by a u64 len, a u32 line and a u32 col, with 0 < len < 256, the path inside `.rodata`, ending in
   `.rs` and free of NUL, and line ≠ 0 and col ≠ 0. The last rule removes 533 (#94) and 571 (#115) slots that
   pass every other rule. All of them have col 0, and one per release is first-party: `base/src/lu.rs`
   line 2 col 0 (#94 slot 0x566eca0, #115 0x64013d8). First-party means the crates `base`, `db`, `evm_rpc`,
   `global_constants`, `info_server`, `l1`, `net_utils` and `node`, accepted in both forms, absolute
   `/home/ubuntu/hl/code_Mainnet/<crate>/src/…` and relative `<crate>/src/…`. Each is normalised to the catalogue form `<crate>/<file>`. Owners are the
   FDEs that contain a lea of the record. An arm reaches an owner at depth 0 when its handler is the owner,
   and at depth 1 when the handler's body contains a byte-scanned rel32 call/jmp, or a RIP-slot call/jmp
   through a RELATIVE slot, whose target is the owner's start. This is an over-approximation. Handlers that
   are dispatcher instances are skipped. An anchor holds when the only arm name that reaches its owners is
   the expected one, and that arm reaches them in all three instances. Direct callers of owners and of
   dispatcher instances come from a byte scan of all of `.text` for rel32 call/jmp.
7. **Qualification.** A path is `absent_path_surviving_variant` when it has Locations only in #94, the
   anchored variant exists in both releases, and the anchor holds in #94. It is `added_path_existing_variant`
   or `added_path_new_variant` when it has Locations only in #115 and the anchor holds in #115. Any other
   pattern gets no qualification. Anchors and qualification use the `[r12]` (`execute`) family only.
8. **RE-010 and sizes.** RE-010's 88 cases are compared arm by arm: arm, path end, instruction count,
   entry branches and first call. Its can1357 labels are compared with the binary names. Handler sizes are
   FDE extents and nothing more.
9. **Census controls.** (a) Every jump table anywhere in `.text`, in any register form, with N
   pairwise-distinct in-FDE entries, is run through the serializer test. (b) Every `mov ebp,0x3b9aca00`
   byte sequence in `.text` is listed with whether a tag load `mov R,[base]` (any R and base) and the idiom
   (either cmov) with tag register R follow it directly.

## Evidence

The analysis covers the stated scope and is not limited by time or address range: every occurrence of each
release's consecutive 64-bit idiom, with either cmov and in any register allocation, is surveyed, and
every occurrence of the default-elsewhere form is listed (Method 3 says what is excluded); every arm of
every dispatcher instance in both families is walked, and both census controls cover all of `.text`. It is
not complete for the binaries as a whole.

### Observations

**O1. VARIANTS tables.** Each release has three copies with identical name lists, not two. They are
distinct arrays: in 73 of 88 (#94) and 77 of 92 (#115) slots the three copies hold three different pointers
(to separate copies of the same text), and in 15 slots all three hold the same pointer (for example #94
slot 0 `noop` 0x20a140 and slot 62 `cDeposit` 0x20ab90). Each serializer's 88 (92) name pointers equal one
copy's exactly and the other two copies' at only those 15 slots (O3).

| release | copies (start) | names | bound slot text | start lea'd by | bound lea'd by |
|---|---|---:|---|---|---|
| #94 | 0x56c46e0, 0x56e8bd0, 0x5733130 | 88 | `variant index 0 <= i < 88` | 4, 4, 2 functions | 2, 2, 1 functions |
| #115 | 0x644cc40, 0x6467f98, 0x649bac8 | 92 | `variant index 0 <= i < 92` | 4, 4, 2 functions | 2, 2, 1 functions |

In every copy, the bound slot is exactly 16·N bytes after the start. Every copy start is found from its lea
reference, never from a gap. The words directly before each copy belong to other data: a Location record
(#94 0x56c46c8, #115 0x644cc28), RELATIVE code pointers (#94 0x56e8bc8; #115 0x6467f88 and 0x6467f90), or
another &str slot (`NoEvmDb` at #94 0x5733120; `variant index 0 <= i < 3` at #115 0x649bab8).
RELATIVE addends and length words are in `objdump-excerpts.txt`, for example #94
`56c46e0 R_X86_64_RELATIVE 20a140` with `noop` at 0x20a140 and length word 4, and slot 1 `approveAgent` at
addends 0x3f3bdd, 0x58a92e and 0x700c87 in the three #94 copies.

**O2. Tag-to-index idiom and the jump tables it leads to.** Occurrences of the consecutive form are counted
over all of `.text`, with either cmov and in any register allocation (Method 3). The dispatchers'
allocation was the first survey's whole denominator; the second survey added the other `cmovae`
allocations; `cmovb` is added here.

| release | form | sites | `direct` | `direct_with_stores` | `after_gap` | `after_bounds_check` | `no_table` |
|---|---|---:|---:|---:|---:|---:|---:|
| #94 | all | 59 | 14 | 1 | 18 | 22 | 4 |
| #94 | `cmovae`, dispatchers' allocation | 34 | 10 | 1 | 9 | 12 | 2 |
| #94 | `cmovae`, other allocations | 17 | 0 | 0 | 5 | 10 | 2 |
| #94 | `cmovb` | 8 | 4 | 0 | 4 | 0 | 0 |
| #115 | all | 68 | 19 | 0 | 19 | 24 | 6 |
| #115 | `cmovae`, dispatchers' allocation | 26 | 12 | 0 | 12 | 0 | 2 |
| #115 | `cmovae`, other allocations | 30 | 0 | 0 | 3 | 24 | 3 |
| #115 | `cmovb` | 12 | 7 | 0 | 4 | 0 | 1 |

| release | form | execute (`[r12]`) | sentinel_other_base (`[r15]`) | serializer | other | no_table |
|---|---|---:|---:|---:|---:|---:|
| #94 | `cmovae`, dispatchers' allocation | 3 | 0 | 11 | 18 | 2 |
| #94 | `cmovae`, other allocations | 0 | 0 | 0 | 15 | 2 |
| #94 | `cmovb` | 0 | 0 | 0 | 8 | 0 |
| #115 | `cmovae`, dispatchers' allocation | 3 | 3 | 11 | 7 | 2 |
| #115 | `cmovae`, other allocations | 0 | 0 | 0 | 27 | 3 |
| #115 | `cmovb` | 0 | 0 | 0 | 11 | 1 |

In all: #94 3 execute, 11 serializer, 41 `other` and 4 without a table; #115 3 execute, 3 `[r15]`, 11
serializer, 45 `other` and 6 without a table.
- **Register allocations** (`idiom_register_forms` in the JSON). A `cmovae` allocation is named by tag,
  index (which also received the default) and, for #94, the lea temporary; a `cmovb` allocation by tag,
  index and default register. #94 has 9: the dispatchers' (`rax`, `rax`, `rcx`) at 34 sites,
  (`rax`, `rcx`, `rdx`) at 10, five more `cmovae` ones at 1 or 2 sites each, and two `cmovb` ones at 4 each
  (tag `rax`, index `r8`, default `rax`; tag `rax`, index `rsi`, default `rcx`). #115 has 8: the
  dispatchers' (`rax`, `rcx`) at 26, (`rcx`, `rax`) at 25, three more `cmovae` ones at 1 or 2 each, and three
  `cmovb` ones (tag and index `r8`, default `rax`, at 7; tag and index `rsi`, default `rcx`, at 4; tag and
  index `rax`, default `rcx`, at 1). Every execute, `[r15]` and serializer site uses the dispatchers'
  allocation. The other allocations add 25 (#94) and 42 (#115) sites: 23 / 38 lead to a table, all classed
  `other`, and 2 / 4 have none.
- **The inverted cmov (`cmovb`).** `lea X,[R-0x74]; cmp R,0x74; mov D32,0x14; cmovb X,D` (#94) and
  `sub R,0x86; mov D32,0x14; cmovb R,D` (#115) compute the same index in X or R. #94: 0x282eea4, 0x335ecd3,
  0x3360ab3, 0x3362e64, 0x3362f37, 0x3363373, 0x48f58a4, 0x48f5a34. #115: 0x2bdb5b8, 0x2bdb924, 0x36c2fa3,
  0x36c3034, 0x36c30f3, 0x36c5687, 0x36c5b03, 0x3d985e2, 0x4d90ba4, 0x4d90d44, 0x4e0fd1c, 0x4e1008c. All
  but #115 0x3d985e2 reach an 88- / 92-entry table indexed by the result, directly or after `mov al,0x2` or
  `xor eax,eax`. These tables have 3 to 18 (#94) and 3 to 36 (#115) distinct targets, so they get no role
  (`other`). Example, #94 function 0x282eea0: `mov rax,[rsi]; lea r8,[rax-0x74]; cmp rax,0x74;
  mov eax,0x14; cmovb r8,rax; lea rcx,[rip+…] # 3f2c78; movsxd r8,[rcx+r8*4]; add r8,rcx; jmp r8`
  (18 distinct targets).
- **Default loaded elsewhere** (listed, not surveyed; `idiom_default_elsewhere`). The bias computation
  directly followed by `cmovb I,D`, with no default load in between, occurs at 10 (#94) and 14 (#115) sites;
  no `cmovae` site of this kind exists. Objdump (`test_default_elsewhere_sites`): 8 (#94) and 11 (#115) are
  followed, directly or after `xor eax,eax`, by `movsxd`, `add` and `jmp` through a base register. Each of
  these lies in a function that also holds a consecutive `cmovb` site with the same default register whose
  table lea loads that base register (for example #94 0x282eecd in 0x282eea0: `mov rsi,[rsi+0x20];
  mov r8,[rsi]; lea r9,[r8-0x74]; cmp r8,0x74; cmovb r9,rax; movsxd r8,[rcx+r9*4]; add r8,rcx; jmp r8`).
  The other 2 / 3 (#94 0x3994e61, 0x45487a1; #115 0x3c3d203, 0x3d9858a, 0x57bc1e1) are followed by a
  compare of the index and a conditional jump back to before the site. These bytes do not show that D still
  holds 0x14 at these sites, nor which table the base register addresses (U5).
- **Gaps.** Every `after_gap` site has exactly one gap instruction: `mov rbx,rdi` (20 sites: 9 in #94, 11 in
  #115), `movabs r12,0x8000000000000000` (#94 0x3362fe9, #115 0x36c5739), `mov al,0x1` (#115 0x36c3003),
  `mov al,0x2` (#94 0x335ecd3, #115 0x36c2fa3), `mov eax,0x1` (#94 0x33632e3, #115 0x36c5a83),
  `xor eax,eax` (#94 0x3360ab3, 0x3362f37, 0x3363373; #115 0x36c30f3, 0x36c5687, 0x36c5b03), a stack reload
  `mov r13/r14,QWORD PTR [rsp+disp32]` (#94 0x335edde and 0x3360b5f, #115 0x36c319f) or
  `lea r8,[rax+0x100]` (#94 0x333fcc7). #94 0x3341eb8 has its table lea directly after the idiom and two
  stack stores before the `jmp`.
- **Bounded tables, in both releases.** All 22 #94 `after_bounds_check` sites are `dec I; cmp I,0x52; ja`
  (I = `rax` at 12 sites, `rcx` at 10; 19 then have `mov rbx,rdi`), each followed by a 0x53-entry table
  indexed by tag index − 1 (28 or 29 distinct targets each). All 24 #115 ones are `dec I; cmp I,0x59; ja`
  (I = `rax` at 22, `rcx` at 2; 23 then have `mov rbx,rdi`) with a 0x5a-entry table (31 or 32 distinct
  targets each). The first survey's contrast, 12 bounded tables in #94 and none in #115, came from matching
  one register allocation, and it does not hold.
- **No jump table.** #94 0x1e8e041 (a bit test), 0x335ecb3 (a byte lookup and `ret`), 0x4c5c362 and
  0x4c5caf2 (each `cmp rax,0x2b; ja; movabs rdx,0x80000006408; bt rdx,rax`); #115 0x36b1573 (range compares
  and `ret`), 0x36c2033 (a byte lookup and `ret`), 0x2d3d5ad, 0x59219f7 and 0x5922397 (each
  `cmp rax,0x2c; ja; movabs rcx,0x100000002080; bt rcx,rax`), and the `cmovb` site 0x3d985e2
  (`cmp rax,0x39; je; cmp rax,0x47; je`).
- **`other` tables** (site, distinct targets of N): #94 0x333fcc7 23, 0x3341eb8 2, 0x3354397 4, 0x335ed34 5,
  0x335edde 88, 0x3360b5f 88, 0x3362b3f 22, 0x3362fe9 5, 0x33632e3 6, 0x39fe710 88, 0x4845c70 88, the 22
  bounded tables and the 8 `cmovb` tables; #115 0x36c2062 23, 0x36c3003 2, 0x36c319f 92, 0x36c535f 22,
  0x36c5739 5, 0x36c5a83 5, 0x3714e67 92, 0x3d17fd0 92, 0x51f5980 92, 0x5b3ea30 92, the 24 bounded tables and
  the 11 `cmovb` tables. The 4 (#94) and 5 (#115) 88- or 92-distinct ones fail the serializer test (no stack
  offset holds VARIANTS[K] for any arm).
- **Sentinel.** The byte sequence `bd 00 ca 9a 3b` (`mov ebp,0x3b9aca00`) occurs 12 times in #94 `.text` and
  15 times in #115 `.text`. Decoded by objdump from the FDE start, 9 per release are `mov ebp,0x3b9aca00`;
  the other 3 (#94) and 6 (#115) lie inside `mov r13d,0x3b9aca00` (`41 bd …`). No test pins this split.
  The sequence is directly followed by a tag load `mov R,[base]` and the idiom with tag register R, with
  either cmov and in any allocation, only at the 3 (#94) and 6 (#115) dispatchers above. R is `rax` at all
  nine; the base is `r12` in all three #94 sites and three #115 sites, and `r15` before the #115 idiom sites
  0x2bda82d, 0x54a2ffd and 0x54a3a6d. The `execute` role is therefore a property of the `[r12]` pin.
- **Entry N.** The rule "read until an entry leaves the FDE" over-reads at 7 of the 14 (#94) and 11 of the 19
  (#115) `direct` tables (18 of 33 and 20 of 38 N-entry tables of any shape), including #115 execute
  instance 1 (0x55f99b0). Table length here therefore rests on N from O1, not on that rule.

**O3. Serializer binding.** 11 functions per release store VARIANTS[K] for every arm K: 88/88 in #94 and
92/92 in #115. In each arm the four &str values sit at four stack slots 0x10 apart: `Action` (len 6),
a PascalCase string, `type` (len 4) and the serde name.
- **Base 0** (`direct` table; strings at [rsp], [rsp+0x10], [rsp+0x20], [rsp+0x30]): #94 0x2821000, 0x2825c00,
  0x334f770, 0x48e3b50, 0x48eaf00; #115 0x2bc95f0, 0x2bd0ef0, 0x36aef70, 0x4d81e00, 0x4d89700.
- **Base 8** (one `mov rbx,rdi` before the table; strings at [rsp+0x8] … [rsp+0x38]): #94 0x281e850,
  0x2823450, 0x334cfa0, 0x3351bc0, 0x48e5fa0, 0x48e8750; #115 0x2bcbbf0, 0x2bce570, 0x36b1600, 0x36b3f80,
  0x4d84400, 0x4d86d80.

The PascalCase strings are identical across the 11 functions of a release. Each function's name pointers
equal one VARIANTS copy's exactly: in #94, 0x281e850, 0x2821000, 0x2823450 and 0x2825c00 match copy
0x56c46e0, 0x334cfa0, 0x334f770 and 0x3351bc0 match 0x56e8bd0, and the four at 0x48e… match 0x5733130;
#115 has the same 4/3/4 pattern. A discriminating example is arm 1: #94 0x2821000 stores
`lea rax,[rip+…] # 3f3bdd` at [rsp+0x30] and 0x334f770 stores `# 58a92e`, the slot-1 addends of copies
0x56c46e0 and 0x56e8bd0. (Arm 62, `cDeposit` 0x20ab90, is one of the 15 shared slots and does not
discriminate.) All 11 use the same bias, default and register allocation as the dispatchers, so the table
index of memory tag t is t−bias when t ≥ bias, else 20. **Census control:** 79 (#94) and 85 (#115) jump
tables in all of `.text`, any registers, have N pairwise-distinct in-FDE entries; exactly these 11 per
release pass the serializer test.

**O4. Execute instances (`[r12]` family).** All arm targets are inside the FDE and pairwise distinct
(88 in #94, 92 in #115).

| release | instance | FDE | table | arms resolved | extended decoder |
|---|---:|---|---|---:|---|
| #94 | 0 | 0x2759240..0x275a376 | 0x3ede28 | 88 | none |
| #94 | 1 | 0x4d83050..0x4d84164 | 0x712dfc | 88 | none |
| #94 | 2 | 0x4d84170..0x4d85284 | 0x712f5c | 88 | none |
| #115 | 0 | 0x2bdbaa0..0x2bdcb65 | 0x60a360 | 92 | none |
| #115 | 1 | 0x55f99b0..0x55faa79 | 0x927b08 | 92 | idx 52 |
| #115 | 2 | 0x55faa80..0x55fbb49 | 0x927c78 | 92 | idx 52 |

Arm indices are observations; the serde names attached to them in O4-O6 are VARIANTS[K] for arm K, which
is inference I2 for these dispatchers.
- **Arm outcomes** (the same in every instance of a release). #94: 84 direct calls, 2 slot calls,
  1 entry-branch handler (arm 63, VARIANTS[63] = `cUserModify`) and 1 arm with no call (arm 0, `noop`).
  #115: 87 direct calls, 2 slot calls, 1 entry branch (arm 63), 1 no call (arm 0) and 1 shared tail
  (arm 91, VARIANTS[91] = `cDeposit2`).
- **Instances call different handlers.** Of the arms resolved in all three instances, 84 of 87 (#94) and
  88 of 91 (#115) reach three pairwise-distinct handler functions. The three exceptions use one target in
  all instances: the slot calls of arms 16 and 40 (#94) / 41 (#115), and the arm-63 entry branch.
- **Arm 52 of #115 instances 1 and 2.** The arm at 0x55fa72e (instance 2: 0x55fb7fe) loads the pointer at
  [r12+0x20] and its first qword (`mov r8,[r12+0x20]; mov rax,[r8]`), then computes
  `lea ecx,[rax+0x7a]; cmp rax,0x86` at 0x55fa736/0x55fa739, `cmovae ecx,eax`, `xor edx,edx`, and ends in
  `call 0x55f99b0` at 0x55fa757 (instance 2: `call 0x55faa80` at 0x55fb827), a self call. RE-010's decoder
  rejects `48 3d`, `0f 43` and `31`; the extended walker resolves both arms and objdump confirms the
  12-instruction path.

**O5. Shared tail and re-entry.**
- **Arm 91 (VARIANTS[91] = `cDeposit2`, I2).** In every `[r12]` instance, #115 arm 91 is
  `mov rcx,[r12+0x8]; jmp` into arm 62 (VARIANTS[62] = `cDeposit`). Instance 0: the jump target 0x2bdc457
  lies inside arm 62 (0x2bdc452), whose path is `mov rcx,[r12+0x28]; mov rdi,rsp; …; call 0x2c6bbf0`. Both
  arms reach handler 0x2c6bbf0.
- **Arm 52 in #94 (VARIANTS[52] = `multiSig`, I2).** Arm 52 calls the 66-byte 0x282ee50, whose rel32 call
  at 0x282ee7e goes to 0x2759240. Instances 1 and 2 do the same through their own 66-byte functions
  (0x48f5850 → 0x4d83050, 0x48f5800 → 0x4d84170).
- **Arm 52 in #115.** Each `[r12]` instance's arm 52 calls the instance itself (0x2bdc843, 0x55fa757,
  0x55fb827).

**O6. The `[r15]` dispatcher family (#115 only).** 0x2bda7c0..0x2bdb225, 0x54a2f90..0x54a39f8 and
0x54a3a00..0x54a4468, tables 0x609f00, 0x92671c and 0x92688c.
- **Shape.** The same sentinel and idiom as the `[r12]` family, with the tag loaded by `mov rax,[r15]`
  (0x2bda82a). The action pointer arrives in `rcx` (`mov r15,rcx`), and the entry computes the gate byte
  inline (`lea ecx,[rax+0x7a]; cmp rax,0x86; …; cmp al,0xe; …; mov ecx,0x501d; bt ecx,eax`), as #115
  execute instance 0 does. #94 has no such dispatcher (O2).
- **Arms.** All 92 arms of each are direct calls to 92 distinct functions, arms 0 and 52 included.
  None of these handlers is a handler of any `[r12]` instance.
- **Relation to the `[r12]` handlers.** For 57, 60 and 60 of the 92 arms, the `[r15]` handler of arm K
  directly transfers to a `[r12]`-family handler of the same index K (byte scan: a rel32 call/jmp, or a
  RIP-slot call through a RELATIVE slot). With rel32 transfers alone the counts are 54, 57 and 57; arms 16,
  41 and 63 count only through RIP-slot calls. For no arm does the handler transfer to a `[r12]` handler that
  is not also a handler of index K. (The `[r12]` handler of arm 62 is also the shared-tail handler of arm 91,
  so the `[r15]` handlers of arms 62 and 91 both reach a handler that serves both indices.) Examples in
  0x2bda7c0: arm 62 → 0x2c17820 and arm 91 → 0x2c0f810 (two distinct 1433-byte functions, both calling
  0x2c6bbf0, so arm 91 does not share arm 62's first call in this family); arm 79 → 0x2c19f20, which calls
  0x283b5b0. The arm-52 handlers 0x2c12690, 0x551cb40 and 0x5536770 call `[r12]` instances 0x2bdbaa0,
  0x55faa80 and 0x55f99b0.
- **Anchors at depth ≤ 1.** user_outcome.rs, vault_transfer.rs and withdraw3.rs are reached only by their
  expected arm in all three `[r15]` instances, at depth 1; impl_outcome_deploy.rs is not reached at depth ≤ 1.

**O7. Entry sequences and references of the dispatchers.**
- **Entry sequences** (objdump, push/sub and branch targets masked; `test_entry_signatures`): all three #94
  instances and #115 instances 1 and 2 are instruction-for-instruction identical (`mov r13,r9; mov r12,r8;
  mov r15,rsi; mov rbx,rdi; test dl,dl; …; cmp cl,0xe; …; bt ecx,eax`). #115 instance 0 differs
  (`mov r15,rcx; mov r13,rdx; mov rbx,rdi; mov r12,[rsi+0x18]` and an inline gate). The three `[r15]`
  dispatchers form a third class.
- **Direct references** (rel32 byte scan of all of `.text`, each confirmed by objdump). Each #94 instance:
  5 call sites in 3 functions plus the first-call target of its arm 52. Each `[r15]` dispatcher: 5 call
  sites in 3 functions. Each #115 `[r12]` instance: its own arm 52 and the arm-52 handler of one `[r15]`
  dispatcher, nothing else. No RELATIVE slot and no RIP lea points at any of the 9 instance starts.

**O8. Locations and anchors.** Under the 8-crate first-party list (Method 6), all 1186 first-party
Locations in #94 use the absolute form and all 1359 in #115 the relative form. Outside it: #94 has 6379
other absolute paths and 10 relative `src/hl_node.rs` records without a crate directory (next to 53
absolute `…/node/src/hl_node.rs`); #115 has 5101 absolute `…/code_Mainnet/z_vendor/…`, 712 relative
`z_forks/…` and 1303 other absolute paths. Records counted under the Method 6 rules: 7575 (#94) and 8475
(#115); without the line ≠ 0 / col ≠ 0 rule there would be 533 / 571 more (all col 0).

Arms are given by index with their VARIANTS[K] name (I2); an anchor holds when only the expected name
reaches the owners, in all three instances (Method 6).

| file | #94 lines (records) | #94 owners reached by | #115 lines (records) | #115 owners reached by |
|---|---|---|---|---|
| `l1/action/c_deposit.rs` | 9 (2) | idx 62 `cDeposit`, depth 0, instances 0-2 | none | - |
| `l1/action/evm_raw_tx.rs` | 158 (2) | idx 8 `evmRawTx`, depth 0, instances 0-2 | none | - |
| `l1/action/user_outcome.rs` | none | - | 55, 59 (4) | idx 79 `userOutcome`, depth 0, instances 0-2 |
| `l1/exchange/impl_outcome_deploy.rs` | none | - | 221, 303 (4) | idx 90 `outcomeDeploy`, depth 1, instances 0-2 (instance 0: `call 0x2c59960` at 0x283c5b6) |
| `l1/action/vault_transfer.rs` | 27 (2) | idx 43 `vaultTransfer`, depth 0, instances 0-2 | 27 (2) | idx 44 `vaultTransfer`, depth 0, instances 0-2 |
| `l1/action/withdraw3.rs` | 16 (2) | idx 47 `withdraw3`, depth 0, instances 0-2 | 17 (2) | idx 48 `withdraw3`, depth 0, instances 0-2 |
| `l1/action/vote_global.rs` | 1289 (2) | idx 20 `VoteGlobalAction`, depth 1, instances 1-2 only | 1504 (2) | not reached at depth ≤ 1 |

Owners, lea sites and direct callers (rel32 byte scan of all of `.text`, each confirmed by objdump):
- c_deposit.rs: 0x1f65f80 (lea at 0x1f65fda), 0x47b8300 (0x47b835a) and 0x47b83f0 (0x47b844a); each is
  called only from its own dispatcher instance's arm 62.
- user_outcome.rs: 0x283b5b0 (leas at 0x283b73d and 0x283beed), 0x567c830 and 0x567d220. Callers: the
  `[r12]` arm 79 of each instance and the `[r15]` arm-79 handlers 0x2c19f20, 0x5503280 and 0x55225f0.
- impl_outcome_deploy.rs: 0x2c59960 (leas at 0x2c59db3 and 0x2c5a91d), 0x55cfe90 and 0x55d1ff0. Callers:
  the arm-90 handlers 0x283c2d0 (at 0x283c5b6), 0x4fe9d90 (0x4fea0f7) and 0x4fea170 (0x4fea4d7), and
  three functions that are not arm handlers of either family: 0x2913750 (0x2913a2d), 0x50d3f40 (0x50d4214)
  and 0x50d3530 (0x50d3804).

Path controls: the basenames `c_deposit.rs` and `evm_raw_tx.rs`, and the source paths
`l1/src/action/c_deposit.rs` and `l1/src/action/evm_raw_tx.rs`, occur 0 times anywhere in the #115 file.
`user_outcome.rs` and `impl_outcome_deploy.rs` (and `l1/src/…` forms) occur 0 times in the #94 file. There
are no Location records for them in either form. (The literal catalogue paths `l1/action/…` occur in
neither file; the JSON counts basenames and `<crate>/src/<rest>` paths and names the fields accordingly.)

**O9. Handlers of the four catalogue variants.** `[r12]` instance 0 (arm index → name per I2); the other
instances are in the JSON.

| variant | #94 handler (bytes, own first-party Location files) | #115 handler (bytes, own first-party Location files) |
|---|---|---|
| cDeposit | 0x1f65f80 (239, `l1/action/c_deposit.rs`) | 0x2c6bbf0 (745, `l1/exchange/impl_abstraction.rs`); instances 1-2: 869 bytes, none |
| evmRawTx | 0x1f661c0 (5707, `l1/action/evm_raw_tx.rs`); instances 1-2: 3847 bytes | 0x2a1dd50 (3617, none) |
| userOutcome | 0x204c4e0 (2112, none) | 0x283b5b0 (2541, `l1/action/user_outcome.rs`) |
| outcomeDeploy | - (no such variant) | 0x283c2d0 (856, none; calls 0x2c59960) |

**O10. An `OutcomeDeploy` serde enum already exists in #94.** #94 function 0x3913400 contains
`lea rdx,[rip+…] # 5b681a` (`OutcomeDeploy`), `lea r8,[rip+…] # 5713558`, `mov ecx,0xd`, `mov r9d,0xa`,
`call 0x2a68270` (0x391402b..0x391404a). 0x5713558 is a RELATIVE &str array of 10 names
(`registerOutcomeToken`, `registerOutcome`, `registerTokensAndStandaloneOutcome`,
`registerTokensAndQuestion`, `settleOutcome`, `settleQuestion`, `changeOutcomeDescription`,
`registerQuestion`, `registerNamedOutcome`, `changeQuestionDescription`) ending in
`variant index 0 <= i < 10`, and `.rodata` holds the matching `variant OutcomeDeploy::…` strings. #115 has
`OutcomeDeployOperation` variant strings and `struct OutcomeDeployAction` instead. No #94 Action variant
is named `outcomeDeploy`.

### Inferences

- **(I1)** The serializer functions are serde-derived `Serialize` instances for an internally tagged enum
  `Action` with tag key `type`. The quadruple matches serde's `TaggedSerializer {type_ident, variant_ident,
  tag, variant_name}`, so the string 0x20 below the serde name holds the Rust variant identifier. The index
  binding in I2 does not depend on this reading: O3 shows directly which string each tag-indexed arm stores.
- **(I2)** In each release, execute arm K handles the variant whose serde name is VARIANTS[K]. O3 shows
  that tag-index K maps to VARIANTS[K] for the type the serializers switch on. The execute instances use the
  identical bias, default, N and register allocation. The Location anchors agree at four indices per
  release: 8, 43, 47 and 62 in #94, and 44, 48, 79 and 90 in #115. Of the #115 anchors, 44 and 48 (+1) and
  79 (−1) sit at shifted positions and 90 is new. The `[r15]` family's handlers reach `[r12]` handlers of the
  same index and none that serves only another index (O6, 57/60/60 of 92 arms), so both #115 families index
  the same enum. This does not rest on declaration order. No `visit_str` decode was done: `visit_str` maps
  names to field indices, while O3 ties memory tags to names directly. Indices that are not anchors (for
  example #115 62 and 8) rest on this inference alone.
- **(I3)** A file named after an action belongs to that action's code, for example c_deposit.rs and
  cDeposit. This is used only as corroboration. The negative controls show that the anchors would detect a
  mis-binding.
- **(I4)** The three `[r12]` instances per release are separately compiled instances of one dispatcher,
  probably monomorphisations. Each recurses into itself for multiSig, and they call different handler
  copies.
- **(I5)** VoteGlobalAction (index 20 = the default index in both releases) is the variant whose payload
  holds the niche below the bias. This is consistent with the idiom, but no payload layout was decoded.
- **(I6)** In #115 the `[r15]` family is the outer action dispatcher, in the position the #94 `[r12]`
  instances hold (5 external call sites in 3 functions each, O7), and the #115 `[r12]` family is entered
  through multiSig (its only external callers are `[r15]` arm-52 handlers, O6/O7). This reading rests on
  direct references only; indirect calls without a RELATIVE slot or lea were not traced. If it holds, the
  `[r12]`-to-`[r12]` join compares #94's outer dispatcher with #115's multiSig-inner one, while their
  handlers are the per-action functions in both releases.

### Unknowns

- **U1.** Whether `c_deposit.rs` and `evm_raw_tx.rs` still exist as source files in #115. They could have
  been deleted, renamed, merged, or kept with no panic site left.
- **U2.** Whether the new `user_outcome.rs` Locations in the existing userOutcome handler come from new
  code or from code moved from another file.
- **U3.** Cross-release handler equivalence. Only FDE sizes were compared. The compilers differ:
  rustc 1.94.1 with LLD 21.1.8 for #94, and rustc 1.95.0 with LLD 22.1.2 for #115 (`.comment`, see the
  excerpts).
- **U4.** Which #115 instance corresponds to which #94 instance. By entry sequence, every #94 instance
  matches #115 instances 1 and 2 and none matches #115 instance 0 (O7). By callers, the #94 `[r12]`
  instances resemble the #115 `[r15]` family (I6). The instance-0/instance-0 pairing used in the tables
  below is a convention; the size-band count ranges from 54 to 60 of 84 over the 9 pairings.
- **U5.** The roles of the `other` jump tables (41 / 45), including the 22 / 24 bounded tables, the 4 / 5
  tables with 88 / 92 distinct targets that are no serializer and the 8 / 11 `cmovb` tables, and of the
  4 / 6 idiom sites without a table (O2). For the 10 / 14 sites whose default register is loaded elsewhere:
  whether that register holds 0x14 there and, for the 8 / 11 that end in `movsxd`/`add`/`jmp`, which table
  they dispatch through (O2).
- **U6.** Payload layouts. Examples are the arm-62 `[r12+0x28]` versus arm-91 `[r12+0x8]` argument
  (cDeposit / cDeposit2 per I2) and the payload of the default-index variant.
- **U7.** (A decoder limitation, not an unknown about the binary.) RE-010's strict decoder cannot read
  #115 `[r12]` instances 1 and 2, arm 52; the extended walker resolves both (O4) and is used nowhere else.
- **U8.** Why `vote_global.rs` is reached only from #94 instances 1 and 2. Instance 0's arm-20 handler
  0x23e8640 (163 bytes; VoteGlobalAction per I2) has no direct transfer to an owner, so the owner may sit
  deeper than depth 1.
- **U9.** What the 1-2 KB `[r15]` handlers do, and why 32-35 of each dispatcher's 92 handlers have no
  direct transfer to a `[r12]` handler.
- **U10.** Whether #94 handled outcome deployment through another action, given the #94 `OutcomeDeploy` enum
  (O10).

## Negative controls

All controls are in `tests/test_action_dispatch_drift.py`. Byte tampers run `analyze` on the mutated
release with its own digest accepted and combine it with the other release.

| control | result |
|---|---|
| RE-010 re-derived with the generic finder (`re010_crosscheck`) | 88/88 cases identical: arm, path end, instruction count, entry branches, first call. The arm decoder is RE-010's own, so this checks table and instance discovery, not decoding |
| RE-010 JSON fields tampered one at a time (digest re-pinned): arm, path end, instruction count, entry branch, first call | each gives `mismatched_indices == [k]` |
| RE-010 JSON dispatcher, table, binary digest or table length changed (digest re-pinned) | fails closed with the identity messages |
| A RE-010 first call is retargeted to another FDE start | detected: `mismatched_indices == [3]` |
| The three VARIANTS copies hold equal names; one copy's length word is changed | fails closed: "VARIANTS copies differ" |
| The bound text is changed to `< 87`; the bound slot is lengthened by one byte | fails closed: "88 names but bound 87"; the longer string is no bound and hits the lea-inside-run rule |
| Copy count 2 expected; a lea added inside a run; the bound lea or the start lea removed (in memory) | each fails closed with its own message |
| Two names made equal, or one name set to `variant ` (in all three copies) | fails closed: duplicate names; not an identifier |
| Two names (61/62) are swapped consistently in all three #94 copies | fails closed: no arm-wise VARIANTS serializer |
| The same swap on the derived name list only | c_deposit.rs anchor fails, reached by `cWithdraw` |
| The table base is shifted ±4 (#94) or +4 (#115) | fails closed: the sentinel site has no N-way in-FDE table |
| The #115 bias is set to 0x74 | fails closed: 2 execute instances |
| In memory, arms are rotated by 1 or −1 (#94) and by 1 or 18 = 0x86−0x74 (#115) | every anchor that held fails |
| #94 constants run on #115 bytes, and the reverse, even with VARIANTS N overridden | fails closed: count mismatch, then "bias block not found" (neither release has the other's idiom form, with either cmov and in any register allocation) |
| Profile fields disagree with the bias-block bytes; the pinned block (the dispatchers' `cmovae` form) ends in `cmovb`; the block is `lea rax,[rax-0x74]; …` (X = R), or the #94 block is read as the `sub` form | fails closed; the last two: "not an instance of idiom form" |
| Swapped binaries, a flipped last byte, a tampered RE-010 JSON; a missing input file | rejected by digest; the CLI exits 2 on the missing file |
| The #94 arm-62 handler lea 0x1f65fda is retargeted to the next Location (withdraw3.rs) | c_deposit.rs anchor and qualification lost; withdraw3.rs is now reached by `cDeposit` (instance 0) and `withdraw3` (all instances) and no longer holds |
| The call at 0x283c5b6 (#115 arm-90 handler to 0x2c59960) is NOPed | impl_outcome_deploy.rs qualification lost |
| The #115 arm-79 call 0x2bdbbaf is retargeted to the arm-44 handler 0x283c6b0 | user_outcome.rs qualification lost; vault_transfer.rs no longer holds |
| `[r15]` index relation: the call at 0x2c1a255 in the `[r15]` arm-79 handler 0x2c19f20 is retargeted from 0x283b5b0 to the `[r12]` arm-44 handler 0x283c6b0 | same-index counts [56, 60, 60]; other-index arms [[79], [], []] |
| The #115 arm-91 jmp target is moved by +1, to its own arm start, or into the arm-0 jmp | no handler; no handler; fails closed ("does not end in a call") |
| The #94 arm-63 entry-branch `jne` is sent past the dispatcher end | fails closed: "jcc … leaves dispatcher" |
| A primary-instance arm gets an encoding only the extended decoder knows (`xor`), or an undecodable byte | fails closed: the primary instance must decode strictly |
| The #94 serializer arm-62 length imm is set to 7; its name lea is pointed at `CDeposit` | that function becomes `other` (87/88) in both cases; 10 serializers remain and the census agrees |
| The #94 call 0x282ee7e (arm-52 first-call target back into the dispatcher) is NOPed | `reenters_94 == [False, True, True]` |
| A serializer site marked with the sentinel; a sentinel on a bounded table; 91 distinct entries | fails closed (role and instance checks) |
| `qualify` with the variant missing in #115, with #115 Locations added, with userOutcome missing in #94 | qualification lost; lost; `added_path_new_variant` |
| Synthetic bytes (no binaries): `_str_slot`, `_stack_strs` (REX.R, non-RIP lea, register overwrite, len 256, non-.rodata); the idiom matcher (other allocations, both cmov polarities, `[r12-0x74]` with SIB 0x24, the `81 /5` form of `sub`; SIB 0x20, X = R, D = X, D = R where the form forbids it, a reversed `cmovb`, a `cmovb` or `cmovae` on another register, `cmovbe`, `cmova`, a wrong immediate, REX.X on the lea or the cmov, a memory source, 32-bit `cmovb`/`cmovae` rejected); the default-elsewhere matcher (both polarities; D = R, D = X, another destination, a default load in between, 32-bit rejected; never both matchers at one offset); the gap rules (stack reload, non-RIP lea and `xor r,r` accepted; `[r12+d]`, mod 00, indexed, REX.X-indexed and RIP-relative lea, `xor` of two registers or of memory rejected); the table matcher (index overwrite, more than 4 gaps, a `cmp` without `ja`, a second bounds check); the sentinel rules (`_sentinel_base` and `sentinel_census` need the tag load into the idiom's tag register, also when that is not `rax`); the extended decoder (accepts exactly its 3 encodings); truncated walks | each listed case gives the stated result |
| Path controls (O8) | 0 Locations, 0 basename and 0 source-path occurrences in the other release |
| Boundaries | handler starts ±1 are not FDE starts; FDE end is exclusive; the strict decoder rejects `cmp rax,imm32` |
| GNU objdump / readelf (skipped when they are not GNU) | the sentinel, tag load, idiom and table of all 9 dispatchers; every idiom site (59 / 68) and every default-elsewhere site (10 / 14) decodes as the stated instructions with the stated registers; what follows each default-elsewhere site (O2); every idiom-site table lea, jmp, gap and bounds-check instruction; the primary arm paths of both families; the two extended-decoder paths; the name stores of one base-0 and one base-8 serializer × N arms; 34 cited sites, every dispatcher reference and every owner caller (linear sweep from the FDE start); every RELATIVE relocation (readelf equals the tool's reader); FDE bounds of dispatchers, serializers and handlers; the entry-sequence classes of O7 |
| Objdump control for the idiom survey, for a cmovcc of any condition and operand form: (A) every `mov r32,0x14` (`B8+r` or REX.W `C7`) followed within 12 bytes by a cmovcc that names that register, with the bias as an immediate of a `cmp`/`sub`/`lea`/`add` among the 5 instructions before the `mov` and up to the cmovcc; (B) every bias instruction on a 32- or 64-bit register (#94 `cmp`/`sub` r,0x74, `add` r,−0x74, `lea` r,[base−0x74]; #115 `cmp`/`sub` r,0x86, `add` r,−0x86, `lea` r,[base−0x86], `lea` r32,[base+0x7a]) followed by a cmovcc among its next 4 instructions, with no jump, call or return in between | every surveyed site (59 / 68) and every default-elsewhere site (10 / 14) is found. The only other hits are the 32-bit byte-truncated form, at #94 0x335eca2 (function 0x335ec90) and at 8 #115 sites (the entries of the three `[r15]` dispatchers and of execute instance 0, two `[r15]` arm-52 handlers, and arm 52 of execute instances 1 and 2), and #115 0x4e417de, `cmp rax,0x86; mov edx,0x0; cmovne rdx,r8` (an equality test, with no default and no biased value) |

The shared-tail re-walk check (Method 5) is a consistency assertion that a linear decoder cannot fail, so
it has no negative control.

## Results

### Variant join (denominators: 88 names in #94, 92 in #115)

This per-variant #94 → #115 drift is the packet's main new result (#226 covers #94 only, and #37 / #9 pair
functions by hashes, not by serde name; Relation to other work).

| class | count | details |
|---|---:|---|
| common names | 86 | |
| same index | 46 | idx 0-22 and 49-71 |
| shifted +1 | 25 | #94 idx 23-47 move to #115 idx 24-48, behind the inserted `validatorL1Status` |
| shifted −1 | 15 | #94 idx 73-87 move to #115 idx 72-86, after the two removals |
| removed | 2 | `voteAppHash` (#94 idx 48, handler 0x1e5f5d0) and `SystemAlignedQuoteSupplyDeltaAction` (#94 idx 72, handler 0x1e64ac0) |
| added | 6 | `validatorL1Status` (#115 idx 23, 0x2b91050), `voteAbciDigest` (87, 0x294fdd0), `activateOutcomeDeployer` (88, 0x2668210), `trailingStop` (89, 0x285d440), `outcomeDeploy` (90, 0x283c2d0), `cDeposit2` (91, shared tail into 0x2c6bbf0) |
| common names whose PascalCase serializer string (Rust identifier per I1) changed | 0 | |

Names and indices come from the VARIANTS tables (O1); the handlers come from the `[r12]` arms and are
attached to names by I2. The full per-variant table follows. Columns 6-9 are execute instance 0 in each
release; instances 1 and 2 are in the JSON (`variant_join[*].handlers_*` and `targets.*.execute_instances`).
Handler sizes are FDE extents in bytes and are **not** a code comparison.

| #94 idx | #115 idx | class | serde name | Rust identifier (I1) | #94 arm (I2) | #94 handler, bytes (I2) | #115 arm (I2) | #115 handler, bytes (I2) |
|---:|---:|---|---|---|---|---|---|---|
| 0 | 0 | same | `noop` | `Noop` | 0x2759452 | no call | 0x2bdbb2f | no call |
| 1 | 1 | same | `approveAgent` | `ApproveAgent3` | 0x27592bd | 0x1e5f770 (754) | 0x2bdc275 | 0x2cf0c40 (1110) |
| 2 | 2 | same | `batchModify` | `BatchModify` | 0x2759a0e | 0x21dfd90 (460) | 0x2bdc191 | 0x2cf02c0 (370) |
| 3 | 3 | same | `cancel` | `Cancel` | 0x2759a95 | 0x22be610 (324) | 0x2bdc21b | 0x2608d60 (383) |
| 4 | 4 | same | `cancelByCloid` | `CancelByCloid` | 0x27598ae | 0x21dff60 (329) | 0x2bdc054 | 0x250f1e0 (388) |
| 5 | 5 | same | `claimRewards` | `ClaimRewards` | 0x2759c55 | 0x2710e30 (1540) | 0x2bdc412 | 0x2bfb830 (1514) |
| 6 | 6 | same | `createSubAccount` | `CreateSubAccount` | 0x2759d2a | 0x27e3140 (1540) | 0x2bdc4c4 | 0x285c7e0 (2491) |
| 7 | 7 | same | `createVault` | `CreateVault` | 0x2759ac2 | 0x1e5f3c0 (401) | 0x2bdc248 | 0x283b2e0 (421) |
| 8 | 8 | same | `evmRawTx` | `EvmRawTx` | 0x2759da0 | 0x1f661c0 (5707) | 0x2bdc53a | 0x2a1dd50 (3617) |
| 9 | 9 | same | `ForceIncreaseEpochAction` | `ForceIncreaseEpoch` | 0x2759998 | 0x21e0a00 (359) | 0x2bdc11b | 0x2399040 (521) |
| 10 | 10 | same | `liquidate` | `Liquidate` | 0x2759d84 | 0x23e66f0 (4106) | 0x2bdc51e | 0x262aa00 (4455) |
| 11 | 11 | same | `linkStakingUser` | `LinkStakingUser` | 0x2759849 | 0x1e60770 (212) | 0x2bdc002 | 0x2cf8e00 (232) |
| 12 | 12 | same | `modify` | `Modify` | 0x275996b | 0x22be760 (250) | 0x2bdc0ee | 0x2939d00 (218) |
| 13 | 13 | same | `NetChildVaultPositionsAction` | `NetChildVaultPositions` | 0x2759cfd | 0x27e8cb0 (1303) | 0x2bdc497 | 0x273f660 (1720) |
| 14 | 14 | same | `order` | `Order` | 0x275977e | 0x1eee7c0 (414) | 0x2bdbf32 | 0x2e41890 (585) |
| 15 | 15 | same | `registerReferrer` | `RegisterReferrer` | 0x2759a3b | 0x27e30a0 (155) | 0x2bdc1be | 0x285c730 (173) |
| 16 | 16 | same | `RegisterValidatorAction` | `RegisterValidator` | 0x27596fd | 0x3367800 (2943, slot call) | 0x2bdbebf | 0x36c8a10 (2469, slot call) |
| 17 | 17 | same | `CValidatorAction` | `CValidator` | 0x2759b0b | 0x2768ff0 (985) | 0x2bdc2cf | 0x2c77640 (1381) |
| 18 | 18 | same | `scheduleCancel` | `ScheduleCancel` | 0x2759d57 | 0x1e5fc40 (162) | 0x2bdc4f1 | 0x283c900 (171) |
| 19 | 19 | same | `setDisplayName` | `SetDisplayName` | 0x2759ee6 | 0x27e2170 (236) | 0x2bdc64d | 0x2392200 (264) |
| 20 | 20 | same | `VoteGlobalAction` | `VoteGlobal` | 0x2759b94 | 0x23e8640 (163) | 0x2bdc353 | 0x29492f0 (169) |
| 21 | 21 | same | `validatorL1Vote` | `ValidatorL1Vote` | 0x2759cd0 | 0x22cdb40 (1127) | 0x2bdc46a | 0x285c300 (1071) |
| 22 | 22 | same | `validatorL1Stream` | `ValidatorL1Stream` | 0x2759e81 | 0x21e0370 (213) | 0x2bdc5f9 | 0x285e110 (253) |
| 23 | 24 | +1 | `validatorL1UpdateReferenceOracle` | `ValidatorL1UpdateReferenceOracle` | 0x2759f78 | 0x27fa570 (199) | 0x2bdc164 | 0x273fdb0 (208) |
| 24 | 25 | +1 | `SetGlobalAction` | `SetGlobal` | 0x27599e1 | 0x1f67b30 (2855) | 0x2bdc137 | 0x2830710 (2801) |
| 25 | 26 | +1 | `setReferrer` | `SetReferrer` | 0x27599b4 | 0x27de270 (163) | 0x2bdc781 | 0x23853b0 (181) |
| 26 | 27 | +1 | `spotDeploy` | `SpotDeploy` | 0x275a01b | 0x23e7d10 (2349) | 0x2bdbe65 | 0x2948700 (2759) |
| 27 | 28 | +1 | `spotUser` | `SpotUser` | 0x27596b4 | 0x21cfec0 (584) | 0x2bdc70c | 0x2ceb570 (901) |
| 28 | 29 | +1 | `spotSend` | `SpotSend` | 0x2759fa5 | 0x1f66070 (329) | 0x2bdc727 | 0x245b750 (354) |
| 29 | 30 | +1 | `SignValidatorSetUpdateAction` | `SignValidatorSetUpdate` | 0x2759fd2 | 0x1e642e0 (309) | 0x2bdc567 | 0x296e160 (321) |
| 30 | 31 | +1 | `subAccountModify` | `SubAccountModify` | 0x2759dcd | 0x22cdfb0 (279) | 0x2bdc2a2 | 0x285d1a0 (306) |
| 31 | 32 | +1 | `subAccountTransfer` | `SubAccountTransfer` | 0x2759aef | 0x1e60d00 (247) | 0x2bdc594 | 0x23994a0 (264) |
| 32 | 33 | +1 | `subAccountSpotTransfer` | `SubAccountSpotTransfer` | 0x2759dfa | 0x1e64420 (263) | 0x2bdbf5f | 0x285e5c0 (280) |
| 33 | 34 | +1 | `tokenDelegate` | `TokenDelegate` | 0x27597ab | 0x1e5fa70 (174) | 0x2bdbe92 | 0x2385470 (186) |
| 34 | 35 | +1 | `twapCancel` | `TwapCancel` | 0x27596d0 | 0x22c4630 (362) | 0x2bdbdde | 0x2a2fb70 (402) |
| 35 | 36 | +1 | `twapOrder` | `TwapOrder` | 0x2759588 | 0x2722790 (5335) | 0x2bdbe0b | 0x29414e0 (604) |
| 36 | 37 | +1 | `updateIsolatedMargin` | `UpdateIsolatedMargin` | 0x275966b | 0x21e2b60 (339) | 0x2bdbcfd | 0x25c0200 (351) |
| 37 | 38 | +1 | `topUpIsolatedOnlyMargin` | `TopUpStrictIsolatedMargin` | 0x27594a0 | 0x21e2ee0 (776) | 0x2bdc754 | 0x285e890 (668) |
| 38 | 39 | +1 | `updateLeverage` | `UpdateUserLeverage` | 0x2759fff | 0x21e0b70 (316) | 0x2bdc631 | 0x25bfd90 (322) |
| 39 | 40 | +1 | `usdSend` | `UsdSend` | 0x2759eb9 | 0x1f64a40 (381) | 0x2bdc081 | 0x2457b20 (397) |
| 40 | 41 | +1 | `ValidatorSignWithdrawalAction` | `ValidatorSignWithdrawal` | 0x27598db | 0x374ec60 (1281, slot call) | 0x2bdc2e9 | 0x44d7210 (1616, slot call) |
| 41 | 42 | +1 | `vaultDistribute` | `VaultDistribute` | 0x2759b33 | 0x1e60020 (168) | 0x2bdc6a7 | 0x283cf80 (180) |
| 42 | 43 | +1 | `vaultModify` | `VaultModify` | 0x2759f2f | 0x22c5fd0 (137) | 0x2bdbc5c | 0x2bde430 (557) |
| 43 | 44 | +1 | `vaultTransfer` | `VaultTransfer` | 0x27593d6 | 0x1e5fb20 (172) | 0x2bdbf05 | 0x283c6b0 (184) |
| 44 | 45 | +1 | `VoteEthDepositAction` | `VoteEthDeposit` | 0x2759751 | 0x1e5feb0 (365) | 0x2bdc5b0 | 0x283cc50 (812) |
| 45 | 46 | +1 | `VoteEthFinalizedValidatorSetUpdateAction` | `VoteEthFinalizedValidatorSetUpdate` | 0x2759e27 | 0x1e64cb0 (227) | 0x2bdc84d | 0x2986330 (234) |
| 46 | 47 | +1 | `VoteEthFinalizedWithdrawalAction` | `VoteEthFinalizedWithdrawal` | 0x275a0fa | 0x27177c0 (679) | 0x2bdbd46 | 0x2c02dd0 (691) |
| 47 | 48 | +1 | `withdraw3` | `Withdraw3` | 0x27594e9 | 0x1f67810 (172) | 0x2bdbf8c | 0x246cd10 (184) |
| 48 | - | removed | `voteAppHash` | `VoteAppHash` | 0x27597d8 | 0x1e5f5d0 (405) | - | - |
| 49 | 49 | same | `govPropose` | `GovPropose` | 0x2759892 | 0x1f68be0 (1084) | 0x2bdc038 | 0x2484830 (1154) |
| 50 | 50 | same | `govVote` | `GovVote` | 0x27593a9 | 0x1f64980 (184) | 0x2bdbc02 | 0x2457a50 (196) |
| 51 | 51 | same | `usdClassTransfer` | `UsdClassTransfer` | 0x275a2a2 | 0x1e60850 (569) | 0x2bdca07 | 0x23989e0 (607) |
| 52 | 52 | same | `multiSig` | `MultiSig` | 0x275a0cf | 0x282ee50 (66, re-enters dispatcher) | 0x2bdc831 | 0x2bdbaa0 (4293, re-enters dispatcher) |
| 53 | 53 | same | `convertToMultiSigUser` | `ConvertToMultiSigUser` | 0x27594cd | 0x1e64010 (451) | 0x2bdbd19 | 0x239ac10 (276) |
| 54 | 54 | same | `approveBuilderFee` | `ApproveBuilderFee` | 0x275a048 | 0x1e60a90 (277) | 0x2bdc7ae | 0x2398cc0 (304) |
| 55 | 55 | same | `startFeeTrial` | `StartFeeTrial` | 0x275a0a2 | 0x21e00b0 (698) | 0x2bdc804 | 0x2385530 (391) |
| 56 | 56 | same | `SystemBoleAction` | `SystemBole` | 0x2759516 | 0x1f69020 (270) | 0x2bdbd7d | 0x29491d0 (284) |
| 57 | 57 | same | `SystemSpotSendAction` | `SystemSpotSend` | 0x2759f13 | 0x1e5fcf0 (439) | 0x2bdc67a | 0x283ca00 (495) |
| 58 | 58 | same | `deployerSendToEvmForFrozenUser` | `DeployerSendToEvmForFrozenUser` | 0x2759805 | 0x1e64c20 (131) | 0x2bdbfb9 | 0x285f290 (140) |
| 59 | 59 | same | `SystemUsdClassTransferAction` | `SystemUsdClassTransfer` | 0x2759f5c | 0x1e64530 (225) | 0x2bdc6d4 | 0x239d920 (241) |
| 60 | 60 | same | `CSignerAction` | `CSigner` | 0x2759937 | 0x21cfdd0 (235) | 0x2bdc0ae | 0x2b70940 (247) |
| 61 | 61 | same | `cWithdraw` | `CWithdraw` | 0x2759bbd | 0x2758800 (731) | 0x2bdc37c | 0x2c697a0 (970) |
| 62 | 62 | same | `cDeposit` | `CDeposit` | 0x2759ca3 | 0x1f65f80 (239) | 0x2bdc452 | 0x2c6bbf0 (745) |
| 63 | 63 | same | `cUserModify` | `CUserModify` | 0x2759a68 | 0x3996230 (419, on entry branch) | 0x2bdc1eb | 0x3c3f420 (377, on entry branch) |
| 64 | 64 | same | `reassessFees` | `ReassessFees` | 0x2759953 | 0x22ce180 (101) | 0x2bdc0ca | 0x2bed270 (2610) |
| 65 | 65 | same | `evmUserModify` | `EvmUserModify` | 0x2759c76 | 0x22cd990 (431) | 0x2bdc425 | 0x283c890 (104) |
| 66 | 66 | same | `reserveRequestWeight` | `ReserveRequestWeight` | 0x2759403 | 0x2758ae0 (390) | 0x2bdbc89 | 0x285e2d0 (153) |
| 67 | 67 | same | `finalizeEvmContract` | `FinalizeEvmContract` | 0x2759735 | 0x22ce0d0 (168) | 0x2bdbee9 | 0x285e210 (177) |
| 68 | 68 | same | `perpDeploy` | `Hip3Deploy` | 0x275a2eb | 0x21dd7e0 (4501) | 0x2bdca61 | 0x29467e0 (6160) |
| 69 | 69 | same | `sendAsset` | `SendAsset` | 0x2759687 | 0x1f678c0 (611) | 0x2bdbe38 | 0x246ce50 (459) |
| 70 | 70 | same | `SystemApproveBuilderFeeAction` | `SystemApproveBuilderFee` | 0x2759360 | 0x1e64620 (158) | 0x2bdbbb9 | 0x239daa0 (170) |
| 71 | 71 | same | `SystemSendAssetAction` | `SystemSendAsset` | 0x2759478 | 0x2728e10 (579) | 0x2bdbce3 | 0x2c33690 (491) |
| 72 | - | removed | `SystemAlignedQuoteSupplyDeltaAction` | `SystemAlignedQuoteSupplyDelta` | 0x275a075 | 0x1e64ac0 (342) | - | - |
| 73 | 72 | -1 | `agentEnableDexAbstraction` | `AgentEnableDexAbstraction` | 0x275a230 | 0x219a7a0 (137) | 0x2bdc7db | 0x2668e80 (149) |
| 74 | 73 | -1 | `userDexAbstraction` | `UserDexAbstraction` | 0x275a286 | 0x1e60e00 (385) | 0x2bdc87a | 0x2399630 (415) |
| 75 | 74 | -1 | `borrowLend` | `Bole` | 0x2759543 | 0x2764b90 (451) | 0x2bdc8b2 | 0x2c74a70 (489) |
| 76 | 75 | -1 | `sendToEvmWithData` | `SendToEvmWithData` | 0x2759b60 | 0x2729060 (3017) | 0x2bdbdaa | 0x2c33880 (2857) |
| 77 | 76 | -1 | `userPortfolioMargin` | `UserPortfolioMargin` | 0x275938d | 0x1e611a0 (384) | 0x2bdc337 | 0x2399a10 (414) |
| 78 | 77 | -1 | `userSetAbstraction` | `UserSetAbstraction` | 0x275a2cf | 0x1e60f90 (378) | 0x2bdbbe6 | 0x23997d0 (408) |
| 79 | 78 | -1 | `agentSetAbstraction` | `AgentSetAbstraction` | 0x2759333 | 0x1e61110 (135) | 0x2bdca34 | 0x2399970 (147) |
| 80 | 79 | -1 | `userOutcome` | `UserOutcome` | 0x275945c | 0x204c4e0 (2112) | 0x2bdbb8c | 0x283b5b0 (2541) |
| 81 | 80 | -1 | `gossipPriorityBid` | `GossipPriorityBid` | 0x2759865 | 0x1e60bb0 (322) | 0x2bdbcb6 | 0x285d2e0 (343) |
| 82 | 81 | -1 | `agentSendAsset` | `AgentSendAsset` | 0x2759821 | 0x27288c0 (1349) | 0x2bdc01e | 0x2c33240 (1102) |
| 83 | 82 | -1 | `hip3LiquidatorTransfer` | `Hip3LiquidatorTransfer` | 0x2759306 | 0x1e641e0 (253) | 0x2bdbfd5 | 0x285e370 (267) |
| 84 | 83 | -1 | `l1ValidatorVoteBridgeDeposit` | `L1ValidatorVoteBridgeDeposit` | 0x27592ea | 0x1e646c0 (463) | 0x2bdbb66 | 0x285eb90 (903) |
| 85 | 84 | -1 | `authorizeAqav2Role` | `AuthorizeAqav2Role` | 0x2759e54 | 0x27e3750 (434) | 0x2bdbb39 | 0x2962880 (534) |
| 86 | 85 | -1 | `stakingLinkDisableTradingUser` | `StakingLinkDisableTradingUser` | 0x2759e9d | 0x1e648c0 (506) | 0x2bdc5dd | 0x2cfe960 (704) |
| 87 | 86 | -1 | `voteL1Hash` | `VoteL1Hash` | 0x275a259 | 0x1e5f010 (420) | 0x2bdc615 | 0x283ad10 (526) |
| - | 23 | added | `validatorL1Status` | `ValidatorL1Status` | - | - | 0x2bdc6f0 | 0x2b91050 (334) |
| - | 87 | added | `voteAbciDigest` | `VoteAbciDigest` | - | - | 0x2bdc896 | 0x294fdd0 (526) |
| - | 88 | added | `activateOutcomeDeployer` | `ActivateOutcomeDeployer` | - | - | 0x2bdbc2f | 0x2668210 (466) |
| - | 89 | added | `trailingStop` | `TrailingStopOrder` | - | - | 0x2bdcabb | 0x285d440 (3267) |
| - | 90 | added | `outcomeDeploy` | `OutcomeDeploy` | - | - | 0x2bdca8e | 0x283c2d0 (856) |
| - | 91 | added | `cDeposit2` | `CDeposit2` | - | - | 0x2bdbb82 | 0x2c6bbf0 (745, shared tail of idx 62) |

### Qualification of the four catalogue paths (denominator: 4 paths)

| path | catalogue list | result | basis |
|---|---|---|---|
| `l1/action/c_deposit.rs` | absent115 | `absent_path_surviving_variant` | #94: 2 Location records (line 9), owned by the arm-62 (cDeposit) handler in all three instances (depth 0). #115: none. `cDeposit` is still idx 62 with dispatched handlers (I2; 62 is not a #115 anchor), but the instance-0 handler is 745 bytes instead of 239 and owns an `l1/exchange/impl_abstraction.rs` Location instead. |
| `l1/action/evm_raw_tx.rs` | absent115 | `absent_path_surviving_variant` | #94: 2 records (line 158), owned by the arm-8 (evmRawTx) handler in all instances (depth 0). #115: none. `evmRawTx` is still idx 8 (I2; 8 is not a #115 anchor); its handler owns no first-party Location (3617 bytes; #94 5707 / 3847). |
| `l1/action/user_outcome.rs` | added115 | `added_path_existing_variant` | #115: 4 records (lines 55 and 59), owned by the arm-79 (userOutcome) handler in all instances (depth 0; also reached at depth 1 from all three `[r15]` dispatchers). The variant existed in #94 at idx 80, and its #94 handler 0x204c4e0 (2112 bytes) owns no first-party Location. |
| `l1/exchange/impl_outcome_deploy.rs` | added115 | `added_path_new_variant` | #115: 4 records (lines 221 and 303), owned by 0x2c59960 / 0x55cfe90 / 0x55d1ff0, which the new arm-90 (`outcomeDeploy`) handlers call directly (depth 1) in all instances. Each owner also has one direct caller that is not an arm handler (0x2913750, 0x50d3f40, 0x50d3530). |

What the four results mean:
- **c_deposit.rs and evm_raw_tx.rs.** These are missing diagnostic paths, not removed actions: both serde
  names survive at the same index, and (I2) their dispatch survives. The surviving handlers are different
  byte sequences (U3), so "unchanged code" is **not** claimed.
- **user_outcome.rs.** This is a new diagnostic path inside an existing action's handler. Whether the code
  there is new or moved is U2.
- **impl_outcome_deploy.rs.** This is a new Location path reached at depth 1 from the new `outcomeDeploy`
  variant; the owners also have callers outside the dispatchers. The binary shows that this dispatch path
  is new. It does not show whether equivalent logic existed in #94: #94 already has a serde enum
  `OutcomeDeploy` with 10 outcome-deployment variants (O10, U10).

### Supplementary: Location-derived drift paths reached from execute arms (depth ≤ 1)

First-party Location paths present in only one release: 24 `absent115` and 35 `added115`. These 59 are a
subset of the catalogue's 28 + 35. The catalogue `absent115` paths `base/err_dur_guard.rs`,
`base/latency_sampler.rs`, `base/raw_mdg.rs` and `l1/time.rs` have no #94 Location record.

| list | paths | with owners | reached from an execute arm |
|---|---:|---:|---:|
| absent115 | 24 | 24 | 6 |
| added115 | 35 | 35 | 7 |

The reached paths and the arms that reach them:
- `base/address.rs`: spotSend, depth 1.
- `base/cumin.rs`: reassessFees, depth 1.
- `base/iter.rs`: 5 arms, depth 1.
- `l1/action/c_deposit.rs`: cDeposit, depth 0.
- `l1/action/evm_raw_tx.rs`: evmRawTx, depth 0.
- `l1/evm/transactor.rs`: evmRawTx, depth 1.
- `base/l1_map/entry.rs`: 15 arms, depth 1.
- `l1/abci/hash_signature_tracker.rs`: voteAbciDigest and voteL1Hash, depth 1.
- `l1/action/user_outcome.rs`: userOutcome, depth 0.
- `l1/c_staking/jailing.rs`: CSignerAction, depth 1.
- `l1/exchange/impl_outcome_deploy.rs`: outcomeDeploy, depth 1.
- `l1/exchange/impl_user.rs`: CValidatorAction, depth 0.
- `l1/raw_signature_tracker.rs`: ValidatorSignWithdrawalAction, depth 1.

These are reach observations only (arm names per I2). Paths reached from many arms, such as
`base/l1_map/entry.rs`, are shared helpers, and no qualification is derived for them. Every depth-1 edge
used here is a rel32 call or a RIP-slot call; no rel32 `jmp` edge is used.

### RE-010 and can1357 labels (denominator: RE-010's 76 claims and 88 cases)

For #94, the names of cases 76-87 and the 51/76 `wire_type` agreement below agree with open PR #226 (head
`ad161cb7dde4e9e6246f831e5fba4c90c8600dee`, `research/work-items/RE-010-dispatch-cases-76-87/README.md`),
which reported them first from the same three VARIANTS copies. They are listed here as a cross-check of
this packet's #94 values, not as a new result.

- **RE-010 re-derived.** RE-010's 88 measured arms and first calls are reproduced exactly: 0 mismatches.
  RE-010's dispatcher 0x2759240 and table 0x3ede28 are #94 execute instance 0. The arm decoding is RE-010's
  own `walk`, so agreement is expected for the arm paths; the new parts are the table and instance discovery.
- **wire_type labels.** Of RE-010's 76 can1357 `wire_type` labels, 51 equal the #94 serde name and 25 do
  not. #226 reports the same split (of the 25: 13 differ by an `Action` suffix, 6 by first-letter case, 5 by
  both, and case 68 otherwise). Added here is the comparison with the serializer's PascalCase string per arm
  (the Rust identifier per I1): in 20 of the 25 the label equals that string. Examples: `ForceIncreaseEpoch`,
  `VoteGlobal`, `VoteAppHash`, and `Hip3Deploy` for serde `perpDeploy` (idx 68), the one mismatch #226
  leaves open: serializer arm 68 stores both strings. The other 5 are lower-camel forms of that string:
  `registerValidator`, `setGlobal`, `systemBole`, `systemSpotSend` and `cSigner`.
- **rust_variant labels.** `rust_variant` equals that string + `Action` for 74 of 76 claims. The two
  exceptions are case 37 (`TopUpIsolatedOnlyMarginAction`; serializer string `TopUpStrictIsolatedMargin`)
  and case 38 (`UpdateLeverageAction`; `UpdateUserLeverage`).
- **Cases 76-87 (agree with #226, not new).** RE-010 left these unnamed. #226 names them by index from the
  #94 VARIANTS copies; this packet's #94 values agree with #226 for all 12 cases in name, arm, first-call
  site and target, and first-call FDE extent. By index (VARIANTS[K] for arm K, I2) they are:
  `sendToEvmWithData`, `userPortfolioMargin`, `userSetAbstraction`, `agentSetAbstraction`, `userOutcome`,
  `gossipPriorityBid`, `agentSendAsset`, `hip3LiquidatorTransfer`, `l1ValidatorVoteBridgeDeposit`,
  `authorizeAqav2Role`, `stakingLinkDisableTradingUser`, `voteL1Hash`. What this packet adds for these
  cases is their #115 counterparts: all 12 names survive, at #115 indices 75-86 (shifted −1).
- **Not an RE-010 error.** RE-010's README already says its names come from the reconstruction and are
  unchecked. This is therefore a correction of the reconstruction's labels, recorded here, and not an error
  in RE-010's measured evidence. RE-010 is not edited.

### Handler sizes (size only; denominator: 86 common names)

- **Usable pairs.** 84 common names have resolved handlers in both releases in every instance pairing.
  noop has no call, and multiSig is excluded because its first call re-enters a dispatcher.
- **Within 0.8-1.25.** 60 of the 84 instance-0/instance-0 pairs fall inside the band. Over all 9 pairings of
  #94 and #115 `[r12]` instances the count is 54 to 60 (0/0: 60; 1/0 and 2/0: 58; the other six: 54), so the
  number depends on the pairing convention (U4).
- **Outliers** (instance 0). These include twapOrder at 0.113 (5335 → 604; #94 instances 1 and 2 are 1469
  bytes), evmUserModify at 0.241, reassessFees at 25.8 (101 → 2610) and vaultModify at 4.07.
- **Instance spread.** Within one release, handler size already differs between instances for 23 of 87
  arms (#94) and 29 of 91 (#115; multiSig's re-entered instances are 4293 and 4297 bytes).

Size agreement says nothing about code identity, and these numbers are not an equivalence measure.

## Leads that did not hold or were refined

The scout notes and the earlier versions of this packet were treated as leads. Results:
- **Two VARIANTS copies.** There are 3 copies per release (O1). The third (#94 0x5733130, #115 0x649bac8) is
  missed by walking a run to its first non-&str neighbour.
- **5 serializers per release.** There are 11 (O3): 6 more put one `mov rbx,rdi` between the idiom and the
  table and store the quadruple 8 bytes higher. The first census required the table directly after the
  idiom and the name at [rsp+0x30]; the census control now covers every N-way table in `.text`.
- **"Not followed directly by a jump table" means no jump table.** In the first survey (the dispatchers'
  register allocation only), 24 (#94) and 14 (#115) sites were not followed directly by a table. 21 / 12 of
  them reach one after a gap or a bounds check, and #94 0x3341eb8 after two stack stores
  (`direct_with_stores`); only 2 per release have none (O2).
- **Every occurrence of the idiom is listed (earlier versions of this packet).** The first survey matched one
  register allocation, the dispatchers' (34 / 26 sites); the second matched every allocation of `cmovae`
  only (51 / 56). With `cmovb` as well, the consecutive form has 59 / 68 sites (O2). The 25 / 42 sites outside
  the dispatchers' allocation are all `other` or without a table, so no serializer, dispatcher or join result
  changes. A further 10 / 14 sites have the same bias and cmov with the default register loaded elsewhere;
  they are listed and not surveyed (O2, U5). The first survey's cross-release contrast, 12 bounded tables in
  #94 and none in #115, does not hold: both releases have them (22 / 24).
- **3 execute instances per release.** That count is a property of the `[r12]` pin. #115 has 3 more
  sentinel dispatchers with `[r15]` (O6), apparently the outer layer (I6).
- **Entry N outside the FDE independently confirms the length.** It holds for instance 0 in both releases.
  It does not hold as independent evidence: the same rule over-reads at 7 of 14 and 11 of 19 direct tables,
  including #115 instance 1 (O2).
- **#115 arm 52 of instances 1 and 2 is unknown.** It is a self call that only RE-010's strict decoder
  could not read (O4, U7).
- **The other dispatchers are copies outside scope.** They are separately compiled instances that call
  different handler functions (O4).
- **59 of 84 size pairs.** The count is 60 of 84 under this packet's stated denominator for the 0/0 pairing,
  and 54-60 over all pairings.
- **c_deposit.rs / evm_raw_tx.rs: "missing diagnostic path, not removed code".** Refined: the action is not
  removed, but the surviving handlers differ and no claim of unchanged code is made.
- **impl_outcome_deploy.rs is "added code".** Refined: it is an added Location path on a new dispatch path;
  #94 already had an `OutcomeDeploy` enum (O10).
- **Held as stated.** 86 common names with 40 shifted, the removed and added names and indices, the arm-91
  (cDeposit2 per I2) shared tail at 0x2bdc457 with [r12+0x8] versus [r12+0x28], the arm-52 (multiSig) first
  calls, and the four Location owners.

## Relation to other work

- **Open #37 and closed #9 (RE-014 release drift).** These pair every `.text` FDE across releases by hashes
  and the call graph. This packet does not hash or pair functions, does not use or restate their class
  counts, and is not offered as a replacement. It adds name-keyed dispatch evidence for one enum. #9, whose
  drift evidence #37 resubmits unchanged, also reports a string-level check of all 28 `absent115` and 35
  `added115` catalogue paths in both binaries (boundary-aware `<crate>/src/<file>` matching; #37 includes
  `node-94-115-paths.json`). This packet's path results are consistent with that report: the four paths
  here occur only in their own release (O8 path controls), and the one-release Location paths
  (Supplementary) are 24 of the 28 and all 35.
- **Merged RE-010 (#21).** RE-010 states three non-claims: no serde tables were decoded, wire names come
  from the reconstruction, and cases 76-87 are unidentified. For #94, open #226 addressed all three by index
  before this packet, and this packet's #94 values agree with it (next item). What this packet adds for
  RE-010 is the arm-wise serializer byte binding of tag index to name (O3, the basis of I2), the Location
  anchors, and the per-arm serializer string (I1) next to RE-010's labels. `tools/exchange_dispatch.py` and
  its packet are unchanged.
- **Open #226** (head `ad161cb7dde4e9e6246f831e5fba4c90c8600dee`, packet
  `research/work-items/RE-010-dispatch-cases-76-87/`, README.md there; #94 only). Overlap: the three
  VARIANTS copies 0x56c46e0, 0x56e8bd0 and 0x5733130; the names of cases 76-87 by index, with their arms,
  first-call sites and targets, and first-call FDE extents (76 → 0x2729060 [..0x2729c29) … 87 → 0x1e5f010
  [..0x1e5f1b4)); and the 51/76 `wire_type` agreement with its split of the 25 differences. This packet's
  values agree with #226 in all of these, and none of them is claimed as new here. #226 states that its
  names are an index match and leaves case 68 (`Hip3Deploy` vs `perpDeploy`) open. It also maps the
  dispatcher's shared tail 0x275a136..0x275a230, which this packet does not. This packet adds the serializer
  byte binding (O3), which explains case 68 (serializer arm 68 stores `Hip3Deploy` as the PascalCase string
  and `perpDeploy` as the serde name), the Location anchors, and its main result: the per-variant #94 → #115
  drift (the join, the #115 arms and handlers per I2, the `[r15]` family and the qualification of four
  paths). No file paths collide; either can merge first.
- **Other PRs.** Bridge work (#187 open, #8 merged), rmp_signable signing (#144 and #145, open) and test
  GNU detection (#51, open) do not cover the Action serde tables or the dispatchers. The GNU detection in
  this packet's tests is local to it.

## Implementation and comparison

Not applicable. This is a static evidence packet with no Rust implementation, build, Cargo.lock or
binary comparison. It makes no reconstruction, equivalence or completion claim.

## Results and limitations

- **Machine-readable results.** These are in `action-dispatch-drift.json`, with the denominators stated
  above. The packet requests no gate change; `research/progress.json` and `research/components.json` are
  untouched.
- **Execute-arm names are inferred (I2).** The serializers bind tag index to name in bytes. The execute
  dispatchers are tied to that by the shared idiom and four anchors per release; non-anchor indices rest on
  I2 alone.
- **Depth-1 reach and the caller lists are over-approximations.** They come from byte scans for e8/e9 and
  RIP-slot transfers. The cited transfer and lea sites, every dispatcher reference and every owner caller are
  confirmed by an objdump linear sweep from each function start, but not every depth-1 edge is.
- **Instance pairing across releases is a convention** (U4). The name join, the arm-to-name binding and the
  anchors hold for every instance separately.
- **Serializer recognition is shape-based.** It needs the four &str stores as RIP lea plus imm32 length on
  the arm's straight-line path, at any stack base. The census control found no further function with the
  shape among all N-way tables in `.text`.
- **Dispatcher selection is pinned.** The roles rely on `mov ebp,0x3b9aca00; mov R,[base]` directly before
  the idiom (R its tag register, `rax` at every dispatcher): exactly 3 `[r12]` sites per release and 3 / 0
  `[r15]` sites, or the tool fails closed.
- **The idiom survey covers one stated form.** Consecutive, in order, 64-bit, either cmov, any registers
  (Method 3). The same bias and cmov with the default register loaded elsewhere (10 / 14 sites) is listed
  without a table, shape or role, because those bytes do not show the default value. The byte-truncated
  32-bit variant is excluded, and index computations without a cmov were not searched. The objdump control
  looks for a cmovcc within 12 bytes after `mov r32,0x14` (with the bias nearby) or among the 4 instructions
  after a bias instruction on a 32- or 64-bit register; bias compares on 8- or 16-bit registers are not in
  that net.
- **Not decoded.** Handler bodies beyond the first call, the `[r15]` handlers, payloads and deserializer
  functions, including the functions that lea VARIANTS and the bound slot.

## Next step

Pair the instances by role rather than by address order. The entry sequences (O7) and callers suggest that
#94's `[r12]` instances correspond to #115's `[r15]` family. For 57, 60 and 60 of that family's 92 arms the
handler transfers directly to the same-index `[r12]` handler (O6); what the `[r15]` handlers do was not
decoded. Decode one `[r15]` handler (for example 0x2c17820, arm 62) to its call of 0x2c6bbf0, and the three
callers of each #94 instance, to test I6. After that, decode the payload deserializers of the six
#115-only variants; one question is whether arm 91 (cDeposit2 per I2) differs from arm 62 (cDeposit) only
in where the handler's argument comes from ([r12+0x8] versus [r12+0x28]).

## Files

- `action-dispatch-drift.json`: the tool output, never hand-edited. Its sha256 is
  `fc00a6b751588761dbca7d4cbc2e887e815d912442a2a3d48ec15c802fa6a75d`, pinned in `verify.py`, the tests and
  `MANIFEST.sha256`.
- `objdump-excerpts.txt`: 105 GNU objdump and readelf windows for representative cited sites, each with its
  exact command and the tool version (header lines dropped, `<…>` labels removed, trailing whitespace
  stripped). The Binutils tests cover the remaining cited sites (Reproduce).
- `verify.py`: checks the manifest (well-formed lines, no duplicates, only regular files, no extra files),
  both digests, regenerates the JSON and compares it byte for byte with the pinned hash, then checks the
  pinned facts. It is valid under `-I` and `-O`, and every failure, including a missing or failing tool
  module, exits 1 with `FAIL`.
- `MANIFEST.sha256`: the sha256 of every other file in this directory.
- Tool: `tools/action_dispatch_drift.py`. Tests: `tests/test_action_dispatch_drift.py`.
