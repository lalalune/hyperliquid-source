# RE-009-db-code-table-94: in node #94, what name does each of the 28 db-hub codes format to, which codes reach the `dhs/{}` path template, and what are the three bucket names?

- **Component ID:** storage (`db/src/db_hub.rs`, `db/src/db_home.rs`; consumers in
  `l1/src/evm/evm_db.rs`, `node/src/aux.rs`, `base/src/daily_liner.rs`).
- **Target release and full SHA-256:** Linux x86-64 **hl-node #94**,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- **Source commit / reference commit:** branch cut from `1f8c67c`; can1357
  reference submodule `999556f` (`references/can1357-hl`), used as leads only.
- **Claim status:** *observation* for the 28 names and their tables, the build
  branch's args pair and template bytes, the template walker's byte rules, the gate
  that selects codes 21..23, the GOT-called consumers, the two 3-entry bucket-name
  formatters, and every cross-check value; *inference* for how the template renders,
  for "relative path", for the bucket-to-wrapper identity and for the type/role labels
  (listed under **Inferences**); *unresolved*: the tag meaning, the runtime config
  byte, and what the `daily_liner.rs` consumers do with the string.
- **Scope included:** the per-code names (both codegen copies), the `dhs/{}` build
  branch, which codes and config-byte values reach it and what it hands the string to,
  the bucket names, and (as cross-checks only) the labels, masks, buckets and gate.
  **Excluded:** the hub `BTreeMap` construction, the bodies of the `daily_liner.rs`
  consumers, snapshot byte formats, runtime behaviour, and any #115/visor claim.

**Bounded question.** In #94, for each index of the 28-entry db-hub code table:
which name does the wrapper's name formatter produce (Display or Debug; the bytes do
not say which), does the wrapper's build branch format the `dhs/{}` template for that
code, and which bucket name goes with its bucket? Answer: 28/28 names (table below);
the build branch is reachable for **codes 21, 22, 23 only** (`EvmTxs`,
`EvmBlockNumbers`, `EvmBlocks`), and not for 10 of the 256 config-byte values;
buckets 0/1/2 are named `Exchange`/`Rpc`/`EvmState`.

## Related work: what open PR #245 already binds, and what is new here

Open PR **#245** (`RE-001-db-code-routing-94`, opened 2026-10-30 21:21Z) binds the
six wrappers, the two 28-entry two-letter label tables, the two masks that select
home keys 0/1/2, the third mask indexed by `(global_byte - 10)` combined with codes
21..23, the global at GOT `0x576e928` -> `0x577b288` + `0x48`, the excluded bytes
`{10, 18..25, 31}`, the bypass sentinel and the six caller windows. **None of that is claimed as new here.** #245 contains no long names, no
`dhs` template, no template decoding, no `daily_liner.rs` consumer and no bucket
names. This packet's new contribution is:

1. the **28 per-code names**, read from the two name formatters (`0x35b67f0`,
   `0x45c4a10`) that the wrappers pass as their format argument;
2. the **`dhs/{}` template** on #245's construction arm, its byte rules (from the
   walker it is passed to), which codes and config bytes reach it, and the two
   `base/src/daily_liner.rs` functions the built string goes to;
3. the **three bucket names**, bound through the two 3-entry formatters of the
   `db/src/db_home.rs:83` panics.

Secondary additions #245 does not make: the EVM-family test (`cmp al,0x6`), a
reference scan showing the wrappers are not address-taken, an aligned `.text`
census of the gate shapes, and the `static_config.rs` initializer behind the global.

**Cross-checks against #245** (this packet decodes these again from the bytes; it
compared #245's `records.json` field by field with `db-code-table.json`):

| item | #245 | this packet | agreement |
|---|---|---|---|
| two-letter labels | 28 per table; `0x56f1920`/pool `0x594ff2`, `0x572d7e0`/pool `0x6f7394`; `Ps` at 4, `ps` at 27 | same tables, same 28 labels | agree, 28/28 in both tables |
| masks | `0x081ffeff`, `0x00e00100`, `0x0020ff01` (values pinned by #245's tool) | same values, decoded from the `mov eax,imm32; bt eax,r12d; jae` chain and the gate | agree, 3/3 |
| home key / bucket | keys 0/1/2, counts 21/4/3, index 27 -> 0 | `home_bucket` per code | agree, 28/28 |
| gate | construction iff code in 21..23 and (`a >= 22` or bit `a` of `0x20ff01` clear), `a = (g-10) mod 256` | build iff `(code-0x15) as u8 < 3` and the same byte condition | agree; per code 246 bytes for 21..23 and 0 otherwise (738 pairs) |
| excluded global bytes | 10, 18..25, 31 | `config_byte_suppressed_values` | agree, 10/10 |
| global binding | slot `0x576e928` -> `0x577b288`, byte `+0x48` | same, plus the `+0x50` once word and the initializer `0x164ff00` | agree |
| bypass sentinel | sign-bit sentinel | `movabs r12,0x8000000000000000` decoded | agree |
| callers | 24, 25, 26, 23, 21, 22 at `0x3269c5c`, `0x3269e77`, `0x326a086`, `0x47f2670`, `0x47f2682`, `0x47f2697` | same (call site, target, code) | agree, 6/6 |
| wrappers | six 1081-byte bodies | same six FDEs | agree, 6/6 |
| Location | `db/src/db_hub.rs:60:18` at `0x56f3a18`, `0x572aec8` | same slots | agree (#245 also reports column 18) |
| census | raw `b8 ff fe 1f 08 44 0f a3 e0` hits = the 6 wrapper sites | aligned census of 9 shapes; raw gate sequence 6 hits | consistent (6) |

No value disagrees. Methods differ: #245 pins the mask values, body hashes and
instruction offsets and checks them; this tool decodes masks, gate immediates and
thresholds from instruction shapes. Terms: this packet's *home bucket* = #245's
*home key*; *build branch* = *construction arm*; *niche* = *bypass sentinel*;
*config byte* = *global-state byte*; *tag* = *label*.

**Other related work.**
- Merged **#7** (`research/work-items/constants`) labels `0x164ff00`
  `StaticConfig::load` and the byte it stores at `+0x48` (`0x164ffc2`) the `AwsName`
  discriminant, and decodes the 76-entry name table `0x5668288`. That is the byte the
  gate reads (see Inferences 6-7). #7 also describes the template byte `0xc0` as an
  "alignment marker" that carries padding bytes; the bytes favour the argument-slot
  reading used here (section 3).
- Merged **#23** (`research/work-items/RE-009-storage-state-roots/`) lists the
  `db_hub.rs:60` Locations and the six wrapper FDEs but decodes no table; nothing
  there is edited.
- Open **#262** (`RE-009-evm-db-blake3`) anchors on the same three `evm_db.rs:154`
  calls (`0x3269c5c`, `0x3269e77`, `0x326a086`), makes no claim about the codes and
  defers their meaning to #245; no conflict.
- This tool imports `tools/state_roots.py`. Open PRs touching that file: #166, #167,
  #169, #185, #240, #247, #254, #261, #269, #275, #280, #287, #293 (fail-closed
  hardening for malformed inputs). Each PR's `tools/state_roots.py` change was applied
  alone to a copy of this tool, and the output hash was unchanged (see Results).

## Reproduce

Platform: macOS (Darwin 25.6.0, arm64). Tools: `python3` 3.13.18 (stdlib only),
GNU `objdump`/`readelf` (GNU Binutils) 2.47.20260726, needed only by the six
GNU-gated tests and the commands below. Linux was not re-run for this revision; the
analysis is static and endian-explicit. No network, no execution of the binary.

Coordinate system: the image is a **PIE** (`ET_DYN`; `e_type` bytes at file offset
`0x10` are `03 00`; `DT_FLAGS_1` has `DF_1_PIE`; `readelf` prints
`DYN (Position-Independent Executable file)`). Addresses are **linked virtual
addresses** with load base 0, as GNU `readelf`/`objdump` print them; runtime address
= load base + VA. `.text` VA `0x1343c80` = file offset `0x1342c80`. Function bounds
are `.eh_frame_hdr` FDEs (end exclusive; `fde_count` 121299). "+0x.." offsets are
from a wrapper's FDE start. Working directory is the repo root.

```
python3 -B tools/db_code_table.py \
  --out research/work-items/RE-009-db-code-table-94/db-code-table.json
python3 -I -B research/work-items/RE-009-db-code-table-94/verify.py        # -> PASS
python3 -O -B research/work-items/RE-009-db-code-table-94/verify.py        # -> PASS
python3 -B -m unittest tests.test_db_code_table -v                         # -> 59 tests OK
```

- Tool output SHA-256 (`db-code-table.json`):
  `e84c625a02abde7376f07c0098799185601fe68723495b084ad997926d331f30`; the same under
  `PYTHONHASHSEED` 0 and 7 (and 99 in the tests), `-I` and `-O`.
- `tools/db_code_table.py` checks the target SHA-256 first and raises
  `EvidenceError` (exit 2) on any mismatch or failed structural check; a missing
  `--binary` exits 2. It reuses `tools/state_roots.py`'s ELF / FDE / relocation /
  `lea` / Location readers by `importlib`, as `tools/state_hashers.py` does.
- One aligned census shape (portable TAB; prints 6):
  `objdump -d -M intel --no-show-raw-insn -j .text artifacts/node/94/hl-node | grep -c "$(printf '\t')add    cl,0xf6\$"`
- One excerpt window (prints the 11 lines of `objdump-excerpts.txt` for it):
  `objdump -d -M intel --start-address=0x35b67f0 --stop-address=0x35b681c artifacts/node/94/hl-node | sed -E 's/ <[^>]*>//g; s/[[:space:]]+$//' | grep -E '^ +[0-9a-f]+:'`
- Shingle check against the reference (prints 0; `REF` is the submodule path):

```
REF=references/can1357-hl python3 - <<'EOF'
import os, re, pathlib
words = lambda p: re.findall(r"[A-Za-z0-9_]+", pathlib.Path(p).read_text())
grams = lambda w: {tuple(w[i:i + 8]) for i in range(len(w) - 7)}
ref = set().union(*(grams(words(os.path.join(os.environ["REF"], f))) for f in
      ("db/db_hub.rs", "db/db_home.rs", "db/owned_db_home.rs", "base/daily_liner.rs",
       "global_constants/static_config.rs")))
mine = set().union(*(grams(words(p)) for p in
      ("research/work-items/RE-009-db-code-table-94/README.md", "tools/db_code_table.py",
       "tests/test_db_code_table.py", "research/work-items/RE-009-db-code-table-94/verify.py")))
print(len(ref & mine))
EOF
```

No progress gate is requested (see Results).

## Evidence (observations)

### 1. Wrappers and the code byte

The tool starts from the two `db/src/db_hub.rs:60` Location slots (`0x56f3a18`,
`0x572aec8`; the `"no entry found for key"` panic, `0x59b509` / `0x6f737e`, len
`0x16`). Each slot is `lea`d three times, giving six FDEs:

| wrapper FDEs (end exclusive) | tag table | name formatter | len / off tables |
|---|---|---|---|
| `0x358cea0..0x358d2d9`, `0x358d2e0..0x358d719`, `0x358d720..0x358db59` | `0x56f1920` | `0x35b67f0` | `0x5953f8` / `0x5954d8` |
| `0x459c6b0..0x459cae9`, `0x459caf0..0x459cf29`, `0x459cf30..0x459d369` | `0x572d7e0` | `0x45c4a10` | `0x6f87b0` / `0x6f8890` |

Each is 240 instructions, and all six are equal after this normalisation (stated
masks): a RIP operand plus objdump's `# target` comment becomes `[rip+REL]`; a direct
`call` target becomes `CALLTGT`; a direct `jmp`/`jcc` target becomes its offset from
the FDE start (or `EXT` outside it). Raw bytes are not compared. The masked fields
that do differ: RIP targets at `+0xe0` (tag table), `+0x222` (name formatter),
`+0x3ae` (panic string copy) and `+0x3b5` (Location), between the two codegen copies
only; call targets at `+0x3fb` (copy-specific) and `+0x426` (per-wrapper unwind-path
callee). The template, every GOT slot and the global are the same in all six
(`test_objdump_wrapper_bodies_and_control_flow`).

At entry (`+0x11..+0x1f`): `mov r14d,esi` (the code), `mov BYTE PTR [rsp+0x7],r14b`
(the byte later formatted), `movzx r12d,r14b` (the `bt` index), `xor ebp,ebp`
(bucket 0). The complete listing of `0x358cea0` is in `objdump-excerpts.txt`.

### 2. The 28 names (new)

The build branch (section 3) passes one (value, formatter) pair whose formatter is
`0x35b67f0` (copy-1 wrappers) or `0x45c4a10` (copy-2). Each formatter is
`movzx eax,BYTE PTR [rdi]; lea rcx,[LEN]; mov rdx,[rcx+rax*8]; lea rcx,[OFF];
movsxd rax,[rcx+rax*4]; add rax,rcx`, then tail-calls slot `+0x18` of the writer
vtable at `[rsi+8]` with that (pointer, length). The `u64` length table ends where the
`i32` rel-offset table starts: `(0x5954d8 - 0x5953f8) / 8 = (0x6f8890 - 0x6f87b0) / 8
= 28`. Both copies decode the same 28 printable names. The names are the formatter's
output whichever trait it implements.

| code | tag | name | bucket | bucket name (inf.) | EVM family | reaches build branch | static caller |
|---:|:--:|:--|:--:|:--|:--:|:--:|:--|
| 0 | cA | Candle | 0 | Exchange | | | |
| 1 | lu | FundingLedgerUpdates | 0 | Exchange | | | |
| 2 | nf | NonFundingLedgerUpdates | 0 | Exchange | | | |
| 3 | bi | BoleInterest | 0 | Exchange | | | |
| 4 | Ps | PortfolioSamples | 0 | Exchange | | | |
| 5 | uf | UserFills | 0 | Exchange | | | |
| 6 | aT | AssetTrades | 0 | Exchange | | | |
| 7 | rh | LegacyRewardHistory | 0 | Exchange | | | |
| 8 | et | ExplorerUserTxs | 1 | Rpc | | | |
| 9 | fH | FundingHistory | 0 | Exchange | | | |
| 10 | aH | AssetCtxHistory | 0 | Exchange | | | |
| 11 | oh | OrderHistory | 0 | Exchange | | | |
| 12 | ts | UserTwapSliceFills | 0 | Exchange | | | |
| 13 | th | TwapHistory | 0 | Exchange | | | |
| 14 | up | UserPositionSamples | 0 | Exchange | | | |
| 15 | ua | UserAggregatedFills | 0 | Exchange | | | |
| 16 | se | SpotEvents | 0 | Exchange | | | |
| 17 | gP | GovProposals | 0 | Exchange | | | |
| 18 | de | DelegatorEvents | 0 | Exchange | | | |
| 19 | dr | DelegatorRewardHistory | 0 | Exchange | | | |
| 20 | vb | ValidatorBucketStats | 0 | Exchange | | | |
| 21 | Et | EvmTxs | 1 | Rpc | yes | yes | `0x47f2682` (aux.rs:252) |
| 22 | En | EvmBlockNumbers | 1 | Rpc | yes | yes | `0x47f2697` (aux.rs:252) |
| 23 | Eb | EvmBlocks | 1 | Rpc | yes | yes | `0x47f2670` (aux.rs:252) |
| 24 | Ea | EvmStateAccounts | 2 | EvmState | yes | | `0x3269c5c` (evm_db.rs:154) |
| 25 | Ec | EvmStateContracts | 2 | EvmState | yes | | `0x3269e77` (evm_db.rs:154) |
| 26 | Es | EvmStateStorage | 2 | EvmState | yes | | `0x326a086` (evm_db.rs:154) |
| 27 | ps | LegacyPortfolioSamples | 0 | Exchange | | | |

"Reaches build branch" is the code-side condition; the config byte can still
suppress it (section 4). "Bucket name" attaches section 6's names to the wrapper's
bucket, which is Inference 3 (JSON `home_bucket_name_inferred`).

### 3. The build branch formats `dhs/` plus the name (new)

At `+0x215` (`0x358d0b5` in wrapper 0) the branch writes one args pair and calls the
format function: `lea rax,[rsp+0x7]; mov [rsp+0x108],rax; lea rax,[0x35b67f0];
mov [rsp+0x110],rax; lea rsi,[0x1dee9f]; lea rdi,[rsp+0x58]; lea rdx,[rsp+0x108];
call [GOT 0x576e040]` (-> `0x1344760`). The pair's value is the code byte the entry
stored at `[rsp+0x7]`. The template at `0x1dee9f` is `04 64 68 73 2f c0 00`.

The capacity pass of `0x1344760` (`0x13447a0..0x1344811`, excerpted and pinned by
`test_objdump_template_walker_rules`) gives the byte rules: `0x00` ends; a byte
`0x01..0x7f` is a literal length; `0x80` takes a `u16` length; any other bit-7 byte
is an argument slot (it sets the "argument before any literal" flag at
`0x13447cd..0x13447d4`, adds nothing to the literal length, and skips
`4*b0 + 2*b1 + 2*b2 + 2*b3` option bytes, 0 for `0xc0`). Under these rules the
template is the literal `dhs/` (4 bytes), one argument slot, end: `dhs/{}`. The tool
walks the template with these rules and requires the slot count to equal the number
of args pairs (1 = 1). The same holds for the other templates used here: `0x1ffb00`
(36-byte literal, 1 slot, 1 pair) and #7's `/static_config` template `0x1ef5f5`
(`c0 0e "/static_config" 00`: a slot, then a 14-byte literal), which
`0x164fb98..0x164fbc5` passes exactly one (value, formatter) pair. #7's reading of
`c0 0e` as a padded piece header would leave that pair unused.

### 4. Which codes reach the build branch (new; gate values cross-checked with #245)

The tool matches the whole gate as one byte sequence (`+0x1c9..+0x215`, 6 raw hits in
`.text`, one per wrapper) and decodes every immediate: `r14 = [GOT 0x576e928]`
(RELATIVE -> `0x577b288`); fast path only if `[r14+0x50] == 0`, else the slow path
(`call [GOT 0x576e8b8]`, then `jmp` back to `+0x1dc`); `movzx ecx,[r14+0x48]`;
`add cl,0xf6`; `cmp cl,0x16; jae +0x20e`; `mov eax,0x20ff01; shr eax,cl`;
`cmp BYTE PTR [rsp+0xc],0x3; setae cl; or cl,al; test cl,1; je +0x215 (build)`;
`movabs r12,0x8000000000000000; jmp +0x2ae`; at `+0x20e`
`cmp BYTE PTR [rsp+0xc],0x2; ja +0x1ff`, falling through to the build branch. The
tool checks that the three short branches land on those three instructions and that
the `setae` and `ja` thresholds differ by one.

Control flow (GNU objdump CFG over all six FDEs, calls assumed to return; landing
pads `+0x3db`, `+0x3e0`, `+0x402`, `+0x407` added as roots):
- the build branch's only predecessors are `+0x1fd` (the `je`) and `+0x213` (the `ja`
  fall-through); no edge from outside enters `(+0x215, +0x2ae)`;
- the merge `+0x2ae` has predecessors `+0x209` (niche `jmp`), `+0x29e`, `+0x2a8`;
  with `+0x1ff` and `+0x215` removed, the `[rbx+0x48]` store (`+0x2da`) is
  unreachable;
- with the three `mov DWORD PTR [rsp+0xc],eax` stores (`+0x40`, `+0xb6`, `+0x318`)
  removed, the gate is unreachable; each store directly follows `lea eax,[r14-0x15]`
  (or that `lea` and `cmp al,0x6`; the tool checks the bytes), and no later `r14` write
  (`+0x1c9`, `+0x24b`, `+0x304`) reaches those `lea`s, so
  `[rsp+0xc] = (code - 0x15) & 0xff`.

So the branch is built iff `(code - 0x15) as u8 < 3` **and**, with
`a = (byte - 10) & 0xff`, `a >= 0x16` or bit `a` of `0x20ff01` is clear: **codes 21,
22, 23**, for 246 of the 256 byte values (suppressed for `{10, 18..25, 31}`). The
three callers that pass 21/22/23 (`aux.rs:252`) can reach it; the three that pass
24/25/26 (`evm_db.rs:154`) cannot. No other code has a static caller (section 7).

### 5. What the built string is handed to (new)

After the format call the branch loads the output String's three words
(`r14 = [rsp+0x58]` capacity, `r15 = [rsp+0x60]` pointer, `rdx = [rsp+0x68]` length)
and makes four GOT calls before the merge (JSON `path_build.consumers`, all
first-party Locations of each target):
- `0x358d102`: `[GOT 0x576ef10]` -> `0x1402050` (`base/src/daily_liner.rs:27:13`),
  with `rdi = &[rsp+0x58]` (its output), `rsi = r15`, `rdx` = length: the string as
  a (pointer, length) pair;
- `0x358d115`: `[GOT 0x576ef78]` -> `0x14019b0` (`base/src/daily_liner.rs:58:51`,
  `base/src/hour.rs:12:13`, `base/src/time.rs:62:44`), with `rdi = &[rsp+0x108]`
  and `rsi = &[rsp+0x58]`, i.e. 0x1402050's output, not the string;
- `0x358d135`: `[GOT 0x576dfe0]` (`R_X86_64_GLOB_DAT memcpy`) copies 0xa8 bytes of
  0x14019b0's output (after `r12 = [rsp+0x108]`, its first qword);
- `0x358d148`: `[GOT 0x576e010]` -> `0x54c8cb0` (no first-party Location) with
  `rdi = r15`, `rsi = r14` after `test r14,r14`: the String's buffer is released.

At the merge, `[rbx+0x48] = r12` (`+0x2da`) is the niche on the skip path, or on the
build path the first qword of 0x14019b0's 0xb0-byte output, whose other 0xa8 bytes
are copied to `[rbx+0x50]`. The string itself is not stored.

### 6. The three bucket names (new)

The two `db/src/db_home.rs:83:13` Location slots (`0x56e9988`, `0x572aef8`) are each
`lea`d once, as the Location operand of a one-argument panic
(`lea rdi,[0x1ffb00]; lea rdx,[LOC]; lea rsi,[args]; call [GOT 0x576e098]`). The
template `0x1ffb00` is a 36-byte literal `db_home contains db_bundle in path: `, one
slot, end. The args pair names a formatter of the 28-name shape:

| function | Location | value slot | formatter | len / off tables | names |
|---|---|---|---|---|---|
| `0x332eba0` | `0x56e9988` | `rsp+0x7` | `0x33dd5b0` | `0x58c280` / `0x58c298` | Exchange, Rpc, EvmState |
| `0x459b500` | `0x572aef8` | `rsp+0xe` | `0x45fb180` | `0x6f8900` / `0x6f8918` | Exchange, Rpc, EvmState |

Both length tables abut their offset tables after 3 entries
(`0x58c298 - 0x58c280 = 0x6f8918 - 0x6f8900 = 0x18`): 0 = `Exchange` (`0x20aa98`,
8), 1 = `Rpc` (3), 2 = `EvmState` (`0x20af38`, 8). Each formatter's only reference is
that panic's `lea` (1 RIP reference, 0 calls, jumps, relocations or absolute copies).

Which byte values those functions format (`test_objdump_db_home_bucket_values`):
`0x332eba0` stores the constant 2 (`mov BYTE PTR [rsp+0x7],0x2` at `0x332ec1e`, the
only instruction naming `[rsp+0x7]` besides the panic's `lea`) and writes
`"EvmState"` (`0x20af38`, length 8) itself; `0x459b500` reads its byte from a two-byte
stack array set to `{0x00, 0x01}` (`mov WORD PTR [rsp+0x1a0],0x100`, the only write
there) with index 0 on entry and 1 on the back-edge, and writes the name from the
pointer/length table `0x572d7c8` / `0x6f8900` (the same length table as `0x45fb180`).
So 0 and 1 are paired with `Exchange`/`Rpc` in `0x459b500`, and 2 with `EvmState` in
`0x332eba0`. The word `db_bundle` occurs once in the file, inside this template
(`0x1ffb12`).

A 3-arm `write_str` function `0x1586ee0` (0 -> `Exchange`, 1 -> `Rpc`, else ->
`EvmState`) is also recorded. Its shape (FDE start with head bytes
`48 89 f0 0f b6 0f 85 c9`, then `je rel8`, `cmp ecx,1`, `jne rel8`, each arm
`lea rsi; mov edx`) has 2 candidates in `.text`; the other, `0x3818cf0`, yields
`Spot`/`Mark`/`ExternalPerp`. The tool picks the one whose strings equal the
formatters' names.

### 7. Cross-checked facts (decoded again; see the #245 table)

- **Masks and buckets.** `mov eax,0x81ffeff; bt eax,r12d; jae +0x53` then
  `mov eax,0xe00100; bt eax,r12d; jae +0x30a`: PRIMARY set -> the entry `xor ebp,ebp`
  (0); AUX set -> `mov bpl,0x1` (`+0x62`); else -> `mov bpl,0x2` (`+0x322`). The
  bucket is the `BTreeMap<u8>` key at `movzx edx,bpl` (`+0x11d`). The CFG test checks
  that these and `pop rbp` (`+0x308`, the epilogue) are the only `rbp` writes, and
  that from each arm only its own write reaches `+0x11d`. Bucket 0 = `{0..7, 9..20,
  27}`, 1 = `{8, 21, 22, 23}`, 2 = `{24, 25, 26}`.
- **EVM family** (not in #245): `lea eax,[r14-0x15]; cmp al,0x6` (two compares per
  wrapper, required equal), i.e. codes 21..26.
- **Callers.** Six rel32 `e8` calls with `mov esi,imm32` codes, in `0x3269ae0`
  (`l1/src/evm/evm_db.rs:154:67`) and `0x47f1590` (`node/src/aux.rs:252:13`); all
  six windows are excerpted.
- **Not address-taken** (not in #245; JSON `references.wrappers`). The tool scans
  `.text` for every `e8`/`e9`/`0f 8x` rel32 field and every RIP ModRM
  (`mod=00, rm=101`) disp32 field (0/1/2/4-byte trailing immediate) that resolves to
  a wrapper start, rel8 branches in the 129 bytes before it, relocations of any type
  with that addend, and absolute qword/dword copies in the file: each wrapper has its
  one `e8` call and 0 of every other form. Jump tables (table-relative offsets) are
  not covered.

## Inferences

1. **Rendering.** The build branch produces `"dhs/"` followed by the name formatter's
   output for the code byte (`dhs/<Name>`): from the walker's capacity-pass rules,
   the 1:1 slot/pair count, and the formatter writing `NAME[code]`. The actual
   rendering (`core::fmt::write`-style code at GOT `0x576e008` -> `0x1571d90`) was
   not traced.
2. **"Relative path"** is an interpretation of a slash-containing string that is
   passed as (pointer, length) to a `daily_liner.rs` function.
3. **Bucket identity.** The wrapper's bucket byte (a `BTreeMap<u8>` key) is the same
   0/1/2 value the db_home.rs:83 formatters name. Basis: the shared `u8` value space,
   and the db_home.rs:83 functions pairing exactly those values with those names. Not
   traced through the hub construction.
4. **Trait.** The 28-name and 3-name formatters are `Display` or derived `Debug`
   impls; the bytes do not distinguish them.
5. **BTreeMap.** The node layout read at the key (`u16` length at `+0x62`, `u8` keys
   from `+0x64`, child edges at `+0x70`, values at `+0x8`) and the
   `"no entry found for key"` panic fit a `BTreeMap<u8, _>` lookup.
6. **Lazy global.** `0x577b288` is a lazy cell: the qword at `0x577b288` (not the GOT
   slot) is RELATIVE -> `0x164ff00`; the word at `+0x50` is `03 00 00 00` statically
   and the wrapper's fast path needs it to be 0, so while it holds the static value a
   wrapper takes the slow path (GOT `0x576e8b8`) before reading `+0x48`. In
   `0x164ff00`, `r14` is the out-pointer (`mov r14,rdi` at `0x164ff0d`) and
   `mov BYTE PTR [r14+0x48],al` (`0x164ffc2`) writes the returned value; that this
   value is what lands at `0x577b2d0` rests on the cell layout.
7. **AwsName (with #7's labels as leads).** The gate byte is `StaticConfig`'s
   `AwsName` discriminant. The suppressed values then index #7's table `0x5668288` as
   10 `Ea2`, 18 `SoloTestnet`, 19 `SoloMainnet`, 20 `LockerTestnet`, 21
   `LockerMainnet`, 22 `RpcTestnet`, 23 `RpcSandbox`, 24 `RpcMainnet`, 25
   `RpcMainnet2`, 31 `SoloSandbox`; #7's default `NvTestnet` (32) gives `a = 22`, the
   `jae` branch, so codes 21..23 build under the default.
8. **Option niche.** `[rbx+0x48..+0xf8)` holds an optional 0xb0-byte value whose
   `None` is the capacity-style niche `0x8000000000000000` in its first qword.
9. **Table span.** The wrapper indexes the tables with no bounds check
   (`movzx r12d,r14b`), so 28 is the table span, not a proven enum domain.

## Negative controls

- **Table lengths.** Tag slot 28 breaks the stride-2 progression in both copies
  (`0x56f1a00` -> `0x202e90` `ff ff`; `0x572d8c0` -> `0x1e98dc` `/hom`); the name
  tables abut at 28 and the bucket-name tables at 3, in both copies. The tool refuses
  a progression that does not terminate and a tag count that differs from the name
  count (both tested).
- **Two codegen copies** must agree on tags (28/28), names (28/28) and bucket names
  (3/3); **all six wrappers** must agree on masks, bucket writes, range tests, the
  whole gate, the template, the args pair and the consumers.
- **Shape is not unique.** The 3-arm `write_str` head pattern above has 2 candidates;
  the bucket Display is chosen by its strings, and breaking its head fails closed
  rather than falling back to `0x3818cf0`.
- **Aligned `.text` census** (16,649,471 instructions; `test_text_census_counts` pins
  every count):

  | shape | aligned hits in `.text` | in the six wrappers |
  |---|---:|---:|
  | `mov eax,0x81ffeff` | 6 | 6 |
  | `mov eax,0xe00100` | 6 | 6 |
  | `mov eax,0x20ff01` | 6 | 6 |
  | `add cl,0xf6` | 6 | 6 |
  | `cmp BYTE PTR [rsp+0xc],0x3` | 6 | 6 |
  | `movzx ecx,BYTE PTR [r14+0x48]` | 1838 | 6 |
  | `cmp cl,0x16` | 1851 | 6 |
  | `shr eax,cl` | 94 | 6 |
  | `cmp BYTE PTR [rsp+0xc],0x2` | 25 | 6 |

  The first five are unique to the wrappers; the other four occur 1838, 1851, 94 and
  25 times. The full gate byte sequence matches 6 times (raw; JSON
  `gate_sequence_hits_in_text`).
- **Inline tag-shaped immediates are not the table.** The same census finds 22
  `mov WORD PTR [..],imm16` equal to a tag (`ts` 10, `et` 9, `de` 3) and 17
  `cmp WORD PTR [reg],imm16` (`Ea`/`Eb`/`Ec` 4 each, at `0x13f59a1`, `0x13f6431`,
  `0x164baf1`, `0x164cdce`; `oh` 5), none inside a wrapper. The `Ea`/`Eb`/`Ec`
  compares lie in #7's `aws_name.rs` / `static_config.rs` clusters, where those are
  `AwsName` names (lead).
- **Tag blobs.** Each 56-byte blob (`0x594ff2`, `0x6f7394`) occurs twice in the file,
  has 28 RELATIVE relocations into it and 0 code references (JSON `tag_blobs`).
- **Label strings** (JSON `label_string_counts`): `DbBundle`, `DbHub`, `DbCode`,
  `WrappedDbHome`, `wrap_home`, `home_bucket`, `timed_liner` 0; `daily_liner` 2;
  `db_bundle` 1.

## Tamper controls (tests)

`tests/test_db_code_table.py` runs `build(mutated, expected_sha256=sha256(mutated))`
so the digest guard does not mask a mutation, and names the guard that must fire.

- **The output follows the bytes:** a tag byte in both copies; a name length in both
  copies; the shared `"Exchange"` bytes (bucket name 0); the `dhs/` literal (`xyz/{}`);
  the family threshold at all 12 compares (threshold 7); the family `lea` disp8 at
  all 18 sites (base 20, build codes 20..22); both `mov bpl` swapped in all six;
  PRIMARY bit 27 cleared in all six (code 27 -> bucket 2); both code thresholds in all
  six (build codes 21..24); the shift bias in all six (suppressed set shifts by 1).
- **Only the cross-wrapper check can catch these** (one non-first wrapper altered
  consistently): both `mov bpl` swapped (`bucket branch writes`); both family compares
  (`range tests`); the PRIMARY mask (`mask set`); the shift bias, and the GOT load
  moved to the next RELATIVE slot (`config gate`).
- **Within-wrapper / structural checks:** first family compare only (`thresholds
  disagree [7, 6]`); the lea before the third `[rsp+0xc]` store (`not the family
  lea`); both `mov bpl` = 2 (`not {0,1,2}`); only the `setae` threshold (`thresholds
  disagree (4 vs 2)`); the gate's `je` target (`branch targets do not close`); the
  args value slot (`not the stored code byte`); the PRIMARY `bt` (`no chain`); the
  global-byte read (`no config-gate sequence`); the family `lea`s blanked in one
  wrapper; the template's `0xc0` set to `00` (`0 argument slots but 1 pair`), and its
  `0xc0`, end byte and length byte altered (`not printable ASCII`); a tag progression
  that does not terminate; a 29th tag in both copies (`tag count 29 != name count
  28`); the code-count bound lowered to 28 (`reaches 32-bit bt wraparound`); a broken
  tag relocation; a single-copy tag, name or bucket-name edit; a broken Display head;
  the wrong binary.
- `test_verify_script_passes` runs `verify.py -I`; `verify.py` prints one `FAIL:` line
  (no traceback) for a missing or malformed manifest, a missing binary or a refused
  build.

## Labels (can1357 leads, not binary facts)

`DbBundle`, `DbHub`, `DbCode`, `WrappedDbHome`, `wrap_home`, "timed liner",
`PRIMARY`/`AUX`, `BTreeMap`, `LazyLock`, `StaticConfig`, `AwsName`,
`Formatter::write_str` are names from `references/can1357-hl` or #7, or type-level
readings; none is a symbol in this stripped binary (counts above). Byte support:
`db_bundle` in the db_home.rs:83 template; `base/src/daily_liner.rs` Locations in the
consumers. JSON keys are this packet's own terms: `home_bucket` (#245's home key),
`config_gate` (the reference's "timed liner" gate, which the binary does not
implement as a code bit), `path_build` (the build branch).

## Implementation and comparison

No Rust implementation is claimed; this is a tooling + evidence packet. Comparison
with `references/can1357-hl` (leads only, never copied):

1. *(Found by #245; cross-check only.)* The reference `DbCode` has 27 members
   (`ALL: [Self; 27]`, codes 0..26); the binary's tables span 28, index 27 = `ps`.
   This packet adds that code 27's name is `LegacyPortfolioSamples` and that the
   reference's own `PRIMARY_HOME_MASK` (`0x081f_feff`) already sets bit 27.
2. *(New.)* The reference has no long names: its `DbCode` variants are named after
   the two-letter labels (e.g. `Ps = 4`, `EtLower = 8`), and no `dhs` string occurs in
   the reference tree. The 28 names here come from the binary's formatter tables.
3. *(Found by #245; cross-check only.)* The reference gates its timed liner by a code
   bit (`TIMED_LINER_MASK`); the binary shifts `0x20ff01` by `(byte - 10)` and ORs
   `(code - 0x15) >= 3`, as #245 reports (its counterexample: code 21 with bytes 0 and
   10).
4. *(New.)* The reference `DbBundle` order `Exchange, Rpc, EvmState` matches the two
   3-entry formatters.

Shingle check (command in Reproduce): 0 shared 8-word sequences between this packet's
README, tool, test and verify script and the reference `db_hub.rs`, `db_home.rs`,
`owned_db_home.rs`, `daily_liner.rs`, `static_config.rs`.

## Results and limitations

Machine-readable results in `db-code-table.json`. Denominators:

- **Names:** 28/28 decoded in 2/2 formatter copies, equal 28/28.
- **Template:** one template, the same bytes in 6/6 wrappers; 1 argument slot, 1 args
  pair. **Codes reaching the build branch:** 3/28 (21, 22, 23); config bytes allowing
  it: 246/256. **Consumers:** 4 GOT calls in the branch, 2 with `daily_liner.rs`
  Locations.
- **Bucket names:** 3/3 in 2/2 formatter copies, equal 3/3; each formatter 1
  reference. **Display candidates** of the stated head pattern: 2.
- **Wrappers:** 6/6 located from 2 Location slots; 240/240 instructions equal after
  normalisation in 6/6.
- **Cross-checks with #245:** 0 disagreements over labels (2 × 28), home keys (28),
  per-code construction counts (28; 738 pairs), masks (3), global binding, excluded
  bytes (10), callers (6), wrapper bounds (6), Location slots (2).
- **Static callers:** 6 sites in 2 functions, passing codes 21..26; no static caller
  passes any of the other 22 codes (0..20, 27), and the wrappers have no other
  reference.
- With each of the 13 open `tools/state_roots.py` PRs listed above applied alone, the
  tool output hash is unchanged.

**No progress gate is requested.** This is a partial storage packet; `storage`'s
component gates stay false. Repository-level `make verify test catalogue-check` were
not run in this clone (its reference submodule is not checked out); no result is
claimed for them here.

**Unknowns.**
- **Tag meaning** (directory component, key prefix or file tag): the tag is
  heap-copied into a `(cap 2, ptr, len 2)` triple at `[rsp+0x10..0x28)`, which the
  merge copies to `[rbx+0x20..0x38)`; its consumer was not traced.
- **Bucket identity** with the hub's keys (Inference 3) and the **runtime config
  byte** (Inferences 6-7): the gate is decoded exactly; the value depends on the
  initializer's input.
- **What `0x1402050` and `0x14019b0` do** with `dhs/<Name>`, and what the 0xb0-byte
  value at `[rbx+0x48]` is.
- **Codes 0..20 and 27** have no static caller and the wrappers are not
  address-taken, so whatever uses them goes through other (for example inlined) code.

**Next question:** what does `0x1402050` (`base/src/daily_liner.rs:27`) do with the
`dhs/<Name>` string (joined to a base directory? opened?), and what 0xb0-byte value
does `0x14019b0` (`daily_liner.rs:58`) build from it?
