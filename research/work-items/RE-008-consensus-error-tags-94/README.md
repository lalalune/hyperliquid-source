# RE-008 — Consensus error-enum niche-tag table (node #94)

- **Component ID:** consensus (the error enum that can1357 places in
  `node/consensus/types.rs`; wire/state error tags)
- **Target release and full SHA-256:** hl-node **#94**,
  `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- **Source commit / reference commit:** repository base
  `1f8c67c63ca4794c9689235471c60297f8a5c985` (main). The can1357 reference
  tree `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23`
  is used **only** as a source of label leads and as a diff target
  (`ConsensusRpcError` in `node/consensus/types.rs`, the IDA seed comments in
  `node/consensus/signed.rs`). Nothing from it is treated as verified.
- **Working directory:** repository root for every command below.
- **Claim status:** observations from the bytes, inferences and unknowns are
  kept in separate sections below. There is no implementation or equivalence
  claim.
- **Scope included:** the map from niche tag to name string in three
  niche-dispatch formatter monomorphs (one serde_json-shaped, two
  core::fmt-shaped), with the dispatch bytes and the table bound; a cross-check
  against a fourth monomorph that passes an explicit index; a census of the
  niche constants stored and compared in seven named consensus FDEs, with
  binary-wide counts as the out-of-scope denominator; and corrections, as
  data, to the merged RE-008 inventory and to the can1357 enum.
- **Scope excluded:** bincode wire discriminants (U1); payload layout of
  dataful variants (U2); every FDE outside the seven censused here; runtime
  behaviour; node #115.
- **Related work:** merged **#25** (RE-008 consensus wire/state inventory).
  This packet corrects one of its tag literals (O6) and takes the four
  verifier FDEs and the selection of the census FDEs from its records. It does
  not edit that packet. Open **#49** (RE-008 timeout-to-round transition, not
  merged) covers five of the seven census FDEs (`0x44adfa0`, `0x47594f0`,
  `0x454aa10`, `0x4b31e70`, `0x44ab560`). It reads the same `0x..2a` value as
  the verifiers' success sentinel (for example the `movabs` at `0x44af548` and
  `0x44b1570`). It decodes neither the tag table nor the formatters, and it has
  no census. Its labels `state_dispatch` and `round_history_lookup` appear here
  only as unverified leads. A read-only `gh pr list --state all` listed 269
  PRs. Going by their titles and file lists, the other PRs that touch
  consensus or RE-008 files (#51, #143, #167, #169, #183, #237, #244, #252,
  #259, #268) harden the merged `consensus_wire` tooling and tests, and none
  of them decodes this table.

## Bounded question

> In node #94, (1) what is the complete map from the niche-encoded tag
> `0x8000000000000000 + k` of the consensus error enum to the name string
> that each formatter arm writes, and (2) in seven named consensus FDEs
> (chosen by provenance, see O5), which niche-form values do the niche
> constants reach at 64-bit stores (and where) and at 64-bit compares?

## Reproduce

```sh
export PATH="/opt/homebrew/opt/python@3.13/libexec/bin:/opt/homebrew/opt/binutils/bin:$PATH"
# regenerate the evidence JSON (stdlib only, deterministic, fail-closed)
python3 -I -B tools/consensus_error_tags.py \
  --out research/work-items/RE-008-consensus-error-tags-94/consensus-error-tags.json
# manifest, regenerated-output byte equality, pinned metrics and facts
python3 -I -B research/work-items/RE-008-consensus-error-tags-94/verify.py
python3 -O -B research/work-items/RE-008-consensus-error-tags-94/verify.py
# negative controls, plus the GNU binutils cross-checks (skipped unless GNU
# objdump/readelf are first on PATH; LLVM's objdump takes other flags)
python3 -B -m unittest tests.test_consensus_error_tags -v
# the cited bytes regenerate byte for byte (needs the recorded GNU objdump)
python3 -I -B research/work-items/RE-008-consensus-error-tags-94/make_excerpts.py --check
```

- **Tool versions:** Python 3.13.18 (`python3`); GNU objdump and readelf
  (GNU Binutils) 2.47.20260726. The tool is pure-stdlib Python and does not
  shell out. objdump and readelf are used only by the cross-check tests and by
  `make_excerpts.py`.
- **Decoder validation** (`test_decoder_lengths_against_objdump`): at every
  instruction start that `objdump -d -M intel --no-show-raw-insn` prints in
  the 11 FDEs used here, the in-tool decoder's length equals the distance to
  the next start. That is **10828 / 10828** starts with **0 mismatches**
  (2263, 806, 803 and 1025 for the four monomorphs; 148, 322, 244, 182, 1336,
  229 and 3470 for the seven census FDEs). The count depends on the flag: with
  raw bytes at objdump's default width, long instructions wrap onto a second
  line, and the same first ten FDEs give 11506 lines instead of 9803.
  `test_census_sites_against_objdump` also checks every census `movabs`,
  store and compare record against objdump's operand text (register, QWORD
  width, base, displacement). The register-propagation rules elsewhere are
  **not** independently validated.
- **Input hash:** the binary SHA-256 above. `build()` recomputes it and raises
  `EvidenceError` on any mismatch (CLI exit 2). Malformed or truncated input
  also raises `EvidenceError`. An `expected_sha256` override exists only for
  the byte-patch controls.
- **Output hash:** `consensus-error-tags.json` SHA-256
  `98cb870229cc0c066c1112293bc5fb121b29bdde03e62ff923a54f9a4fe56cb0`. It is
  byte-identical under `PYTHONHASHSEED=0/7/99`, `-O` and `-OO`.
- **Platform:** macOS arm64 (Darwin 25.6.0) reading a Linux x86-64 ELF. The
  work is static only: the target is never executed, and the tool uses no
  network.
- **Coordinate system:** **linked virtual address**. An instruction start
  **includes any REX prefix**. Jump-table entries are little-endian `sdata4`
  values relative to the table base. Niche words are 64-bit little-endian.
- **JSON encoding:** addresses, niche values, tags and indices are hex
  strings. Counts and string lengths are decimal integers. Keys are sorted.

## Method

`tools/consensus_error_tags.py` reuses the ELF, FDE and relocation readers of
`tools/state_roots.py` through `importlib`, as `tools/state_hashers.py` does.

1. **Dispatch heads.** From each FDE start up to the first branch, the tool
   tracks constants and argument provenance. It requires `rcx = 2^63` and
   `rax = word0` (`*rdi`, `**rdi` or `*rsi`, pinned per monomorph) at the
   pinned *select* bytes `4831c1 4885c0 b827000000 480f48c1`
   (`xor rcx,rax; test rax,rax; mov eax,0x27; cmovs rax,rcx`). The only
   instructions allowed between those bytes and `lea rcx,[rip+table]` are ones
   that do not branch and leave rax and rcx alone. The pinned *tail* bytes
   `48630481 4801c8 ffe0` (`movsxd rax,[rcx+rax*4]; add rax,rcx; jmp rax`) must
   follow the `lea`, and the table must equal the pinned VA. Any deviation
   raises.
2. **Table bound.** The tool reads `sdata4` entries until one leaves the FDE.
   The bound is the in-FDE run length that at least two of the three copies
   share, and every copy's run must reach it.
3. **Arms.** Each arm is walked: unconditional `jmp`s are followed and `jcc`
   fall-through is taken. A walk that leaves the FDE or exhausts its budget
   raises. The **name** is the first rodata string that the arm hands to a
   writer (`lea rsi,[rip+p]` + `mov edx,len` + a call, or a tail `jmp reg`).
   Later strings with `len >= 2` are field keys. All three copies must agree
   on `(name, length)` for every tag, or the tool raises.
4. **Explicit-index cross-check.** The same head check runs on monomorph
   `0x4752890`. Its arms are searched for the first call made with
   `(rsi, edx)`, `ecx` and `(r8, r9d)` all set from rip-relative leas and
   immediates.
5. **Census.** Each niche constant (`movabs r, 0x80000000000000xx`, found by
   linear decode and compared with a raw byte-pattern count) is propagated
   through registers across the FDE's control flow (add/sub/lea/inc/dec only
   on 64-bit forms). Every 64-bit store and compare that a tracked niche-form
   value reaches is recorded, together with the store's base, displacement
   and source register. Narrower stores and compares are counted separately
   (there are 0).
6. **Corrections and denominators.** The decoded table is diffed against the
   merged RE-008 inventory and the can1357 enum. The census immediates are
   counted across the whole of `.text`.

## Evidence — Observations (from the bytes)

### O1. The 42-row table (k = 0x00..0x29), agreed by all three formatter copies

| copy (FDE) | jump table | shape of the name write (computed `name_sink_histogram`) |
|---|---|---|
| `0x4753d60`..`0x47564bf` | `0x6f9c44` | 42/42 names passed to `call 0x49c6940`, after `'{'` `'"'` byte pushes (excerpts [1], [6]) |
| `0x44c4480`..`0x44c52ae` | `0x6f2af0` | 23 `call reg` + 19 tail `jmp reg`, writer loaded from `[r15+0x18]` (excerpts [2], [7]) |
| `0x244e3f0`..`0x244f211` | `0x3e23e8` | 23 `call reg` + 19 tail `jmp reg`, writer loaded from `[r15+0x18]` (excerpts [3], [7]) |

All 42 rows agree three-way on `(name, length)`. In **37 / 42** rows each copy
has its own name pointer, so the agreement covers three independent sets of
string bytes. In **5 / 42** rows all three copies point at one merged string:
`0x00` Hardfork `0x20a280`, `0x08` QcGenesisInvalid `0x207420`, `0x0c`
BadBlockProposer `0x206560`, `0x1a` ClientBlockUnexpectedCommitProof
`0x20c540` and `0x29` NetUtils `0x20b018` (flag `shared_name_ptr`). For those
5 rows the agreement covers the path from jump table to arm to pointer, but the
string bytes are read only once (control `test_shared_string_patch_is_not_cross_checked`).
Arms whose names have equal lengths can share one `mov edx,len` tail. For
example, k=0x25 does `lea rsi,...; jmp 0x44c4e7e` into k=0x1c's
`mov edx,0x14`. This happens for 2 / 42 rows in copy `0x4753d60` and 8 / 42 in
each of the other two (`name_len_sites_shared_by_several_tags`).

| k | name | len | field keys (copy 0x4753d60) |
|---|---|---|---|
| 0x00 | Hardfork | 8 | hardfork |
| 0x01 | SignableContentVerifySignature | 30 | |
| 0x02 | VerifyQcSignature | 17 | |
| 0x03 | BadBlockRound | 13 | block_round, last_commit_round |
| 0x04 | BadBlockQcRound | 15 | |
| 0x05 | BadBlockTcRound | 15 | |
| 0x06 | BlockAlreadyRegistered | 22 | |
| 0x07 | QcRoundBeforeHardfork | 21 | |
| 0x08 | QcGenesisInvalid | 16 | |
| 0x09 | QcNoQuorum | 10 | |
| 0x0a | TcNoQuorum | 10 | |
| 0x0b | TcNoTimeout | 11 | |
| 0x0c | BadBlockProposer | 16 | proposer, expected |
| 0x0d | EmptyValidators | 15 | |
| 0x0e | DuplicateBlockRound | 19 | known_block, new_block |
| 0x0f | TimeoutRoundMismatch | 20 | round, expected |
| 0x10 | AlreadyHaveTimeoutFromNode | 26 | |
| 0x11 | RpcNotFound | 11 | |
| 0x12 | RpcRoundRobin | 13 | |
| 0x13 | RpcPeer | 7 | |
| 0x14 | NoClientBlocks | 14 | |
| 0x15 | ClientBlockQcRound | 18 | round, expected |
| 0x16 | ClientBlockQcHash | 17 | hash, expected |
| 0x17 | ClientBlockTx | 13 | |
| 0x18 | ClientBlockTxHashes | 19 | |
| 0x19 | ClientBlockTime | 15 | |
| 0x1a | ClientBlockUnexpectedCommitProof | 32 | |
| 0x1b | ClientBlockMissingCommitProof | 29 | |
| 0x1c | ClientBlockMissingTx | 20 | |
| 0x1d | CommitProofChildQc | 18 | |
| 0x1e | CommitProofGrandchildQc | 23 | |
| 0x1f | CommitProofConsecutive | 22 | |
| 0x20 | RpcRequest | 10 | |
| 0x21 | NodeMsgDeserialize | 18 | |
| 0x22 | ValidatorIPMismatch | 19 | validator |
| 0x23 | AddTxDuplicate | 14 | tx_hash |
| 0x24 | AddTxCommitted | 14 | tx_hash |
| 0x25 | AddTxNotSignedAction | 20 | |
| 0x26 | TxUnexpectedBroadcaster | 23 | tx_hash |
| 0x27 | TxInvalidBroadcasterNonce | 25 | tx_hash, err |
| 0x28 | MissingValidatorSetRound | 24 | |
| 0x29 | NetUtils | 8 | |

Per-copy arm addresses, name pointers, the length-immediate site and the
complete ordered string list are in `consensus-error-tags.json` (`tags[].copies`).

### O2. Dispatch bytes

All three copies carry the same 10-byte `movabs rcx,0x8000000000000000`
(`48b90000000000000080`), directly followed by the pinned select bytes, and
the same pinned tail after `lea rcx,[rip+table]`. The tool computes
`identical_across_copies = true` by comparing those windows (`core_contiguous`
is also true). The windows start at `0x4753d75`, `0x44c448e` and `0x244e401`,
and the `cmovs` instructions are at `0x4753d8a`, `0x44c44a3` and `0x244e416`
(excerpts [1]–[3]). word0 provenance is `*rdi` for the first two copies
(`mov rax,[rdi]`) and `**rdi` for `0x244e3f0` (`mov r14,[rdi]` then
`mov rax,[r14]`). Read as x86, the enforced bytes compute
`k = word0 ^ 2^63` when `word0 < 0`, and otherwise the `cmovs` default `0x27`,
which is the row **TxInvalidBroadcasterNonce**.

### O3. Table bound

The in-FDE runs of the three tables are **47, 42, 42**, so the bound is
**42** (k = 0x00..0x29). The slot at index `0x2a` points at `0x44ca284` in
copy `0x44c4480` (FDE end `0x44c52ae`) and at `0x244f516` in copy `0x244e3f0`
(FDE end `0x244f211`), both outside the FDE. In the 10079-byte copy
`0x4753d60` it points at `0x4754af0`, the same arm as index `0x29`, and the
table bytes continue past it (excerpt [5] dumps 43 entries of each table). The
first value past the table, `0x800000000000002a`, is materialised by
`movabs r13,0x800000000000002a` at `0x47b01c9` (excerpt [10]).

### O4. Explicit-index cross-check (fourth monomorph `0x4752890`)

FDE `0x4752890`..`0x4753d5f` uses the same select and tail bytes with jump
table `0x6f9b9c` (in-FDE run 43). There, rcx = 2^63 comes from
`movabs r12,0x8000000000000003` (`0x47528a1`) followed by `lea rcx,[r12-0x3]`
(`0x47528ae`), and word0 is `*rsi` (excerpt [4]). In **11 / 42** arms the walk
reaches a call made with `(rsi, edx)` = `0x6fb968` "Error" / 5, `ecx` = an
index and `(r8, r9d)` = a name. In **11 / 11** the index equals k and the
name equals the table row. The tags are 0x01, 0x06, 0x10, 0x13, 0x17, 0x1c, 0x20, 0x21,
0x25, 0x28 and 0x29; for example arm 0x1c is
`lea r8 -> 0x6fbb2d; mov r9d,0x14; mov ecx,0x1c; call 0x4aa7fc0` at
`0x4753850`..`0x475386a` (excerpt [8]). The other 31 arms do not match that
register pattern and are not resolved.

### O5. Census of niche constants in seven named FDEs

**Selection.** The seven FDEs were chosen by provenance, not by a closure
rule:

- the four FDEs of merged #25's `verifiers` record, `0x47b01b0`, `0x4758d70`,
  `0x47594f0` and `0x454aa10` (lead labels `verify_signed_block`,
  `verify_qc`, `verify_tc` and `verify_signed_timeout`, which come from the
  can1357 IDA seed comments in `signed.rs` via #25 and are unverified);
- `0x4b31e70`, the callee of `0x47b01b0` through slot `0x5773628` (#25
  verifiers edge; no lead label adopted);
- `0x44ab560` and `0x44adfa0`, two of #25's six functions that hold
  `node/src/consensus/state.rs` Locations (`0x44adfa0` has the #49 lead label
  `state_dispatch`).

The tool records the **13** direct and slot call edges among them
(`census_call_edges`). `0x44adfa0` calls `0x4758d70`, `0x47594f0`,
`0x454aa10` and `0x44ab560`. `0x47b01b0` calls `0x4b31e70`, `0x4758d70` and
`0x47594f0`. `0x47594f0` calls `0x454aa10`, and `0x454aa10` calls
`0x4758d70`. Census labels are neutral (`fde_0x...`). FDE bounds `[lo, hi)`
are in `census[].fde`/`fde_end`.

**Out-of-scope denominator** (raw `REX.W B8+r imm64` byte pattern over all of
`.text`, mapped to FDEs, not validated as instruction starts outside the
census). `0x8000000000000028` occurs in **13** FDEs and `0x800000000000002a`
in **47**. The census covers 3 of each; for example the #25 state.rs
functions `0x2043f70`, `0x22bf220` and `0x44b3200` contain `0x..2a` and are
not censused. `0x8000000000000000` occurs in 11471 FDEs. These immediates are
not specific to one type, so the counts bound candidate FDEs, not error
constructions. No claim is made about any FDE outside the seven.

**Results** (machine-readable in `metrics.census`; every site's instruction is
in excerpt [12]):

- **55** niche `movabs` sites, found by linear decode. That equals the 55 raw
  pattern hits, all 55 at instruction starts. **55 / 55** reach at least one
  store or compare, and 0 exceed the propagation budget. Base immediates:
  `0x47b01b0` 1×`0x..2a`, `0x4758d70` 3×`0x..28`, `0x47594f0` 6×`0x..2a`,
  `0x454aa10` 5×`0x..28`, `0x4b31e70` 6×`0x..28`, `0x44ab560` 1×`0x..00`,
  `0x44adfa0` 33×`0x..2a`.
- **31** `(store site, value)` records with k in `0x01..0x29`, at **27**
  distinct store addresses, covering **14** distinct k. Under the type-identity
  inference (I4) those k name AlreadyHaveTimeoutFromNode, BadBlockProposer,
  BadBlockQcRound, BadBlockTcRound, EmptyValidators, MissingValidatorSetRound,
  QcGenesisInvalid, QcNoQuorum, QcRoundBeforeHardfork,
  SignableContentVerifySignature, TcNoQuorum, TcNoTimeout,
  TimeoutRoundMismatch and VerifyQcSignature (`variant_if_same_enum`).
  Destinations: **16 / 31** are `[rsp+disp]`, which are stack slots, some
  passed by address (for example `0x47595d2` stores to `[rsp+0x28]`, then
  `lea rdi,[rsp+0x28]; call 0x4b1a270`). **15 / 31** go through the register
  that the FDE's entry block copies from rdi (`rbx`, `r14` or `rbp`;
  `dest_class = entry_rdi_copy`). 0 / 31 use any other base.
- Other stores: **5** of `2^63` (k = 0; field `variant_if_error`), **7** of
  `0x..2a` (the first value past the table), and **2** out-of-range (`0x..2c`
  at `0x44ae089` to `[rsp+0xa0]`, `0x..2d` at `0x44ae4a7` to
  `[rsp+0x620]`). 0 narrower stores.
- **37** compares: **31** against `0x..2a`, **5** against `2^63` and **1**
  against `0x..03` (`0x44b049e`, `cmp [rsp+0x4a0],rax`; the same slot is
  compared with `0x..2a` at `0x44b0430`). 0 narrower compares.

**Worked examples** (byte-exact). FDE `0x47b01b0` (excerpt [10]): the shared
store `0x47b03a1 mov [rbx],r13` receives `0x..0c` via `add r13,-0x1e`
(`0x47b039d`), `0x..04` via `add r13,-0x26` (`0x47b0480`), `0x..05` via
`add r13,-0x25` (`0x47b0489`), and the unmodified `0x..2a` via the `je` at
`0x47b041e` and `0x47b0442`. The results of the callees `0x4b31e70`,
`0x4758d70` and `0x47594f0` are compared with r13 = `0x..2a` at `0x47b0205`,
`0x47b040a` and `0x47b043e`. On inequality the callee's whole 0x50-byte
result is copied to `[rbx]`: `0x47b03a6`..`0x47b03e4` after the slot call,
and `0x47b0448`..`0x47b0477` after the other two. FDE `0x47594f0` (excerpt
[11]) builds `0x..28` (`0x47595cd`, `0x4759663`), `0x..0b` (`0x4759673`) and
`0x..0f` (`0x4759689`). At `0x4759936`, `test bpl,bpl` checks the low byte of the
value returned through slot `0x5776ae8` at `0x4759865` (`mov ebp,eax`).
Non-zero stores the unmodified `0x..2a` at `0x4759677`; zero first applies
`add r12,-0x20` (`0x..0a`). Full per-site lists are in
`consensus-error-tags.json` (`census[]`).

### O6. Corrections (data)

- **Merged RE-008 `consensus-wire.json`** inventories
  `ClientBlockMissingTxCommitProof` as one 31-character tag literal (5 times in
  that file, including an `exact` text match). Its 3 rodata occurrences
  (`0x3e3f51`, `0x6f518a`, `0x6fbb2d`) each begin `ClientBlockMissingTx` (20)
  and continue into `CommitProofChildQc` (18) at +0x14 (excerpt [9]). All
  **4 / 4** lea sites that the merged packet records for those anchors pair
  with length **20**: `0x244ed87` and `0x44c4e77` (`mov edx,0x14` at
  `0x244ed8e` and `0x44c4e7e`, excerpt [7]), `0x475527e` (`mov edx,0x14` at
  `0x4755285`, excerpt [6]) and `0x4753850` in the fourth monomorph
  (`lea r8` + `mov r9d,0x14` at `0x475385c`, excerpt [8]). The table rows are
  `0x1c` ClientBlockMissingTx (20) and `0x1d` CommitProofChildQc (18). No
  string of length 31 is written by any decoded arm
  (`strings_of_token_len_written_by_any_arm = 0`). This is recorded here as an
  observation; the merged packet is not edited.
- **can1357 `ConsensusRpcError`** (31 variants) vs the 42 decoded rows:
  **21** binary names are absent from can1357 and **10** can1357 names have no
  decoded row (full lists in `corrections`). can1357 splits
  `SignableContentVerifySignature` into `SignableContent` + `VerifySignature`,
  fuses `RpcPeer` + `NoClientBlocks` into `RpcPeerNoClientBlocks`, and names
  the CommitProof trio `ChildQcCommitProof` / `GrandchildQcCommitProof` /
  `Consecutive`. It omits Hardfork, QcGenesisInvalid, BadBlockProposer,
  ClientBlockUnexpectedCommitProof, MissingValidatorSetRound, NetUtils and the
  AddTx*/Tx*/RpcRequest/NodeMsgDeserialize/ValidatorIPMismatch family. It also
  lists `Error`, `PeerTimedOut` and `IncorrectRpcResponseVariant`, which have
  no decoded row, and it carries the same 31-character token.

## Evidence — Inferences (named, not byte-forced)

- **I1. Names.** The names are the strings the formatters write. Treating them
  as the Rust variant identifiers is an inference, because a serde name can be
  renamed. The lengths and bytes are observations.
- **I2. Formatter shapes.** Copy `0x4753d60` looks serde_json-shaped: it
  pushes `'{'` and `'"'` bytes, then calls a direct buffer writer. The other two
  look core::fmt-shaped: they call a writer through `[r15+0x18]`, which is
  consistent with `dyn fmt::Write::write_str`. Which of the two is Debug and
  which is Display is not determined. Three-way field-key agreement is not
  claimed.
- **I3. The dataful variant.** The `cmovs` default `0x27`
  (TxInvalidBroadcasterNonce) is taken when word0 is not negative. This is
  read as the one variant whose first word is ordinary data, i.e. the niche
  holder. The index and the bytes are observations.
- **I4. Type identity.** The census FDEs are taken to build values of the same
  enum that the formatters dispatch on. Supporting evidence:
  - every censused base immediate is `0x..00`, `0x..28` or `0x..2a`;
  - 31 of the constructed values fall inside the 42-row range;
  - `0x..2a` is exactly the first value past that range (O3);
  - callee results are compared with `0x..2a` and, when unequal, propagated
    unchanged (O5);
  - in `0x47b01b0`, `0x..0c` is stored only on the edge where the 16+4-byte
    compare at `0x47b023e`..`0x47b026a` fails. That edge passes `0x1e2d6a`
    (bytes `DUnexpected proposer for block. Is execution behind?`) to the call
    through slot `0x576e978` and writes two 20-byte payloads to `[rbx+0x8]`
    and `[rbx+0x1c]`; row 0x0c has field keys `proposer`, `expected`;
  - in `0x47594f0`, `0x..0a` (TcNoQuorum) is stored on the path where the
    byte returned through slot `0x5776ae8` is zero; the non-zero path stores
    `0x..2a`.

  None of this proves the types are identical. None of the seven FDEs refers
  to the four monomorphs directly: there is no rel32 call or rip-relative lea
  to them, and none of their 174 rip-slot calls has a relocation that targets
  one.
- **I5. `0x..2a` is the success value.** It is read as the `Ok`/success value
  of a Result-like return type that niche-fills the error enum, on the evidence
  in I4 (compare-and-propagate, the `test bpl,bpl` branch). The 7 stores of
  `0x..2a` are then success returns or initialisations.
- **I6. Index order.** The 11/11 explicit indices in O4 equal k, which fits
  rustc giving niche values in declaration order and serde passing the
  declaration index. The "Error" string in `(rsi, edx)` fits serde's
  container-name argument. Both readings are leads only (U1, U6).
- **I7. Values in the state-dispatcher slots.** `0x..2c` and `0x..2d` are
  stored to the same stack slots as `0x..28` (`[rsp+0xa0]`, `[rsp+0x620]`),
  which suggests a wider enum that nests this one there (U5). Compares
  against `2^63` are read as `Option::None` checks, for example
  `0x47b041a cmp [r14+0x68],rax` with `rax = 2^63`.
- **I8. Return slot.** `entry_rdi_copy` stores are read as writes to the
  caller-provided return slot. The census does not prove that the register
  still holds rdi at the store.

## Evidence — Unknowns / not resolved

- **U1. Bincode wire discriminants.** k is the in-memory niche index. The
  bincode (gossip/RPC) discriminant is written by a separate serializer that is
  not located here. Monomorph `0x4752890`, with its explicit index for 11 / 42
  arms, is the lead.
- **U2. Field keys for nested and dataful variants.** Only the direct keys of
  copy `0x4753d60` are reported. `ValidatorIPMismatch`, for example, emits
  `validator` directly and delegates `node_ip`/`expected_ip` to a nested
  serializer. The payload layout of dataful variants is unresolved.
- **U3. k = 0 / 2^63 ambiguity.** A stored `2^63` word cannot be told apart from
  an Option-like `None` by word0 alone. The census therefore records it with
  `variant_if_error: "Hardfork"` and does not assign a label.
- **U4. Census precision.**
  - Values are tracked through registers only. A tag that is spilled and
    reloaded, or built inside a callee, is not followed.
  - The walk is path-insensitive. It follows both arms of every `jcc` and the
    fall-through after every call, including calls that may never return; `ud2`,
    `int3` and `hlt` end a path. So a recorded `(site, value)` pair has not been
    proven reachable.
  - Only the seven FDEs above are covered.
- **U5. The type of the state-dispatcher slots** `[rsp+0xa0]` and
  `[rsp+0x620]` in `0x44adfa0`, which receive niche values up to `0x..2d`, and
  of `[rsp+0x4a0]` (compared with `0x..2a` and `0x..03`).
- **U6. The Rust type name.** The bytes pass "Error" (5) next to each explicit
  index. can1357 calls the type `ConsensusRpcError` and lists an `Error`
  variant. Neither name is verified.
- **U7. The 31 arms of `0x4752890` without an explicit-index call.** Their
  register pattern is not decoded.

## Implementation and comparison

Not applicable: this is static research tooling. No Rust reconstruction, build
or binary comparison is claimed. No progress gate is requested, and the
consensus component gates stay false.

## Negative controls (`tests/test_consensus_error_tags.py`)

Each tamper rebuilds through `build(mutated, expected_sha256=sha256(mutated))`,
so the sha gate is exercised separately from the claim under test. A control
that expects a failure asserts its specific `EvidenceError` message with
`assertRaisesRegex`. Instruction patches first check the expected original
bytes at the patch site; table-entry and rodata patches read their original
bytes from the binary.

| control | test | expected |
|---|---|---|
| wrong binary / wrong pinned sha | `test_wrong_binary_rejected` | raises `sha256` |
| truncated input (4 lengths) | `test_truncated_input_fails_closed` | raises `malformed input` |
| `mov edx,0x14` -> `0x13` at `0x4755285` (copy 0x4753d60) | `test_length_patch_breaks_three_way_agreement` | raises `disagree` |
| per-copy string byte `0x6fbb40` | `test_per_copy_string_patch_breaks_agreement` | raises `disagree` |
| shared string `Hardfork` at `0x20a286` | `test_shared_string_patch_is_not_cross_checked` | boundary: row becomes `Hardfoxk`, no raise |
| copy 0x244e3f0 table entry 0x1c := entry 0x1d | `test_jump_table_nudge_breaks_agreement` | raises `disagree` |
| table 0x6f9c44 entry 0 out of the FDE | `test_jump_table_entry_out_of_fde_fails_closed` | raises `leaves FDE before the bound` |
| lea displacement +4 at `0x44c44ad` | `test_dispatch_lea_displacement_mismatch` | raises `dispatch table 0x6f2af4 != pinned` |
| copy 0x44c4480 `cmovs`, `mov eax,0x27`, `xor`; copy 0x244e3f0 `test` | `test_dispatch_select_corruption_second_copy` | raises `select bytes not found` |
| `movabs rcx` imm 2^63 -> 2^62 | `test_dispatch_rcx_constant_corruption` | raises `rcx != 2^63` |
| `mov rax,[rdi]` -> `[rsi]` at `0x4753d72` | `test_dispatch_word0_provenance` | raises `word0 provenance *rsi != *rdi` |
| copy 0x44c4480 movsxd scale, `add`, `jmp rax` | `test_dispatch_tail_corruption_second_copy` | raises `tail bytes` |
| arm 0x1c of copy 0x244e3f0 jumps out of the FDE | `test_arm_walk_leaving_fde_fails_closed` | raises `walk left the FDE` |
| FDE lookup off an FDE start | `test_fde_lookup_requires_fde_start` | raises `is not an FDE start` |
| `movabs r13` -> `r11` at `0x47b01c9` | `test_census_unresolved_site_is_counted` | resolved drops to 54 / 55 |
| propagation budget 2 | `test_census_budget_overflow_is_recorded` | site listed as unresolved |
| `mov [rbx],r13` -> `r13d` at `0x47b03a1` | `test_census_narrow_store_is_separated` | 4 narrow records, 0 in-range |
| rdi overwritten before `mov rbx,rdi` | `test_entry_rdi_copy_requires_live_rdi` | `dest_class` becomes `other` |
| `add r13,-0x1e` -> `-0x18` at `0x47b039d` | `test_census_delta_byte_dependence` | `0x47b03a1` relabelled RpcRoundRobin |
| fourth monomorph `mov r9d,0x14` -> `0x13` | `test_variant_index_name_mismatch_fails_closed` | raises `fourth monomorph arm 0x1c` |
| 31-character token copied to `0x1e2d40` | `test_spans_two_tokens_is_computed` | that occurrence does not span |
| all arm-0x1c lengths -> 31 | `test_disputed_token_as_one_variant_is_detected` | `is_single_variant_in_binary` becomes true |
| `.eh_frame_hdr` version byte | `test_eh_frame_hdr_corruption_fails_closed` | raises `eh_frame_hdr` |
| `PYTHONHASHSEED=0/7/99`, `-OO`, non-pinned `--binary` | `test_hashseed_invariance`, `test_cli_under_OO_and_wrong_input` | identical output; exit 2 |

The GNU-gated class `ConsensusErrorTagsGnuCrossChecks` adds independent
oracles:

- `test_all_rows_against_objdump` checks all 42 rows of all three copies:
  jump tables via `objdump -s`, each arm's first `lea rsi`/`mov edx` pair
  before a writer via `objdump -d`, and the name bytes via `objdump -s`;
- `test_census_sites_against_objdump` checks every census record;
- `test_decoder_lengths_against_objdump` checks the decoder;
- `test_fde_ranges_against_readelf` checks all 11 FDE ranges and the total
  FDE count;
- `test_readelf_sections_match_tool` checks the section headers;
- `test_excerpts_regenerate` checks that the excerpts regenerate.

## Results and limitations

The `metrics` block of `consensus-error-tags.json` is pinned by `verify.py`.

- **Tag table:** **42 / 42** rows agree three-way (denominator: 42 tags × 3
  copies). **37 / 42** rows have per-copy name pointers; 5 / 42 share one.
- **Dispatch:** the select and tail bytes are enforced in all 3 / 3 copies
  and observed identical (excerpts [1]–[3]); default `0x27` =
  TxInvalidBroadcasterNonce.
- **Table bound:** 42, from in-FDE runs 47 / 42 / 42. In 2 / 3 copies the
  `0x2a` slot leaves the FDE.
- **Explicit index:** **11 / 42** arms of `0x4752890` resolved, 11 / 11 with
  index = k and the same name.
- **Census (7 FDEs, 5931 instructions):** 55 / 55 `movabs` sites resolved.
  There are 31 in-range store records (27 addresses, 14 k; 16 to rsp slots
  and 15 through the entry rdi copy), 5 `2^63` stores, 7 `0x..2a` stores,
  2 out-of-range stores and 37 compares (31 / 5 / 1). Binary-wide, the
  immediates `0x..28` and `0x..2a` occur in 13 and 47 FDEs, of which 3 and 3
  are censused.
- **Corrections:** 1 merged-packet tag literal spans 2 rows, and 4 / 4 of its
  lea sites pair with length 20. 21 binary names are absent from can1357 and
  10 can1357 names have no decoded row.
- **Limitations:** U1–U7 above. The decoder is length-validated on exactly
  these 11 FDEs (10828 instructions); it is not a general disassembler.

**Next question:** locate the bincode serializer for this enum (U1). Check
whether it writes the explicit index that `0x4752890` passes, which equals k
for 11 / 42 arms, and resolve the remaining 31 arms.

## Packet files

| file | role |
|---|---|
| `consensus-error-tags.json` | tool output (sorted keys; encoding rule above) |
| `objdump-excerpts.txt` | the cited bytes: objdump windows with raw instruction bytes, the jump tables, rodata pools and every census site, each with its exact command |
| `make_excerpts.py` | regenerates `objdump-excerpts.txt` (`--check` compares byte for byte; needs the recorded GNU objdump) |
| `verify.py` | fail-closed verifier (manifest incl. subdirectories, regenerated byte equality, pinned metrics and facts) |
| `MANIFEST.sha256` | SHA-256 of every packet file except itself |
| `README.md` | this file |
