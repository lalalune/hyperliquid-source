# l1-shared: extra-agent name length and count cap, checked against node #94 bytes

- Component ID: `l1-shared` (agent state; "Agent, system-user, nonce, timing and other
  cross-cutting state"). No RE task row covers agents; this is a bounded component packet.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository base `1f8c67c63ca4794c9689235471c60297f8a5c985`;
  reference leads `references/can1357-hl` @ `999556f6e0a474b8312db96ec3149e1c44e97c23`,
  files `l1/agent_tracker.rs` and `l1/exchange/handlers/01_approve_agent3.rs`. They are used
  only as claims to test (table below). Nothing is copied.
- Claim status: observation for every byte-level fact under Evidence; inference for role
  names (save function, equity, foundation-signer branch); unresolved items at the end.
- Scope included: the one rodata message
  `Extra agent name must be between 1 and 16 characters long.`, its error `Display` arm and
  enum tag, the one store of that tag, the FDE-bounded function holding it (the "save"
  function), that function's name-length guard, error drop path, extra-agent count load,
  count cap, cap bypass addresses and too-many error, the GOT slot that holds the function,
  every indirect call through that slot, and the tier derivation in each caller.
- Scope excluded: how the caller parses and normalises `agent_name` before the call
  (trimming, the reference's 100-byte input limit and "valid_until" command form), the
  equity value producer (direct call before the tier block), the list scanned by the
  fixed-tier-10 branch, the unnamed/main-agent path, the name-replace path, the
  valid-until checks, and node #115.

## Reproduce

Working directory: repository root. Platform used: macOS arm64 under a `sandbox-exec`
profile with no network, Python 3.12.1 (standard library only), Apple LLVM objdump 17.0.0
for the optional human cross-check. The binary is only read. Nothing is executed.

```
python3 tools/extra_agent_admission.py --out research/work-items/l1-shared-extra-agent-admission-94
python3 -m unittest tests.test_extra_agent_admission -v
(cd research/work-items/l1-shared-extra-agent-admission-94 && shasum -a 256 -c MANIFEST.sha256)
# optional cross-check (GNU: objdump -d -M intel ...)
objdump -d --x86-asm-syntax=intel --start-address=0x3421e20 --stop-address=0x3421e70 artifacts/node/94/hl-node
objdump -d --x86-asm-syntax=intel --start-address=0x34221af --stop-address=0x3422280 artifacts/node/94/hl-node
objdump -d --x86-asm-syntax=intel --start-address=0x27677c9 --stop-address=0x27678c4 artifacts/node/94/hl-node
```

The tool refuses input with a different SHA-256. It prints:

```
{"admitted_name_bytes": [1, 16], "arm_tags": [83], "bypass_addresses": 3, "caller_forms": 1,
 "callers": 3, "callers_ok_tag_equals_display_entries": 3, "cap_base": 3, "cap_error_tag": 87,
 "cap_matches_reference_formula": true, "cap_per_tier": 2, "display_entries": 390,
 "equity_gate": 10000000, "got_slots": 1, "message_leas": 1, "tag_stores": 1, "tier_clamp": 40,
 "tier_divisor": 10000000000, "tier_offset": 10}
```

It also writes `evidence.json`, `callers.tsv` and `windows.txt` (the raw bytes of every
decoded window). Their hashes are in `MANIFEST.sha256`. Run time is about 3 s.

## Evidence

Coordinates are ELF virtual addresses. For `.text` the file offset is VA − 0x1000. For
`.rodata` and `.eh_frame*` the VA equals the file offset.

1. Message and tag:
   - The 58-byte message occurs once in `.rodata`, at 0x59ce33.
   - Exactly one `lea r64,[rip+disp32]` in `.text` loads it: 0x38004b8, inside FDE
     0x37ffd40..0x38033eb.
   - That function starts `movzx eax, word [rdi]` and then makes an indirect jump through
     the relative `i32` table at 0x59a8d0. The table has 390 entries whose targets fall
     inside the FDE.
   - The arm holding the LEA (0x38004ad) is `write_str(msg, 0x3a)` through the formatter
     vtable, and only table index **83** reaches it.
2. Constructor:
   - Exactly one `mov word [base], 83` exists in `.text`: `66 41 c7 07 53 00` at
     0x3421e58, inside FDE 0x3421e20..0x34224de (1,726 bytes).
   - A relative relocation puts that function's address in GOT slot 0x5774dc0. It is the
     only slot that holds it.
3. Name-length guard. These are the function entry bytes, locked in `windows.txt`:
   ```
   mov [rsp+0x30],r9 ; mov rbp,r8 ; mov r15,rdi ; mov r13,[r8+0x10]
   lea rax,[r13-0x11] ; cmp rax,-0x11 ; ja 0x3421e70
   mov eax,[rip→0x577ab98] ; test eax,eax ; jne init ; mov word [r15],0x53
   ```
   - The ok branch is taken iff `(n − 17) mod 2^64 > 2^64 − 17` (unsigned), with
     `n = [r8+0x10]`. That is exactly **1 ≤ n ≤ 16**. The tool derives this interval from
     the decoded `k = −0x11`, `c = −0x11` and `ja`, and checks the boundaries
     0, 1, 16, 17 and 2^64−1.
   - The `jne init` path performs a one-time initialisation (`call [0x576e8b8]` with
     `esi = 1`) and jumps back to the same tag store.
4. What `n` is:
   - After the tag store, the error path runs `mov rsi,[rbp]` (rbp = r8),
     `test rsi,rsi`, `jne 0x3422339`.
   - At 0x3422339 it runs `mov rdi,[rbp+8]`, `xor edx,edx`, `call [0x576e010]`, then returns
     r15 (the out-pointer) in rax.
   - The GOT slot 0x576e010 relocates to 0x54c8cb0, which begins
     `endbr64 ; cmp rsi,0x1000`. That is a sized-free fast path taking the size in rsi.
   - So `[r8]` is the allocation capacity and `[r8+8]` the pointer. The third word,
     `[r8+0x10]`, is the length of the owned byte buffer.
   - In every caller, r8 points to `rsp+0xc0`. Its three words are copied from an
     `Option<String>`-shaped value whose first word is tested against
     `0x8000000000000000` (the `None` niche) before the call (manual objdump at
     0x27674a2/0x27675ae; not tool-checked).
   - The length is therefore measured in **UTF-8 bytes, not characters**. A name of six
     4-byte characters (24 bytes) is rejected even though the message says "16 characters".
5. Count cap. The two exits that do not find an existing agent of the same name lead to
   0x34221af:
   - 0x3421fbc: the record count is 0;
   - 0x3421fd7: the 0x38-stride loop compares each record's `+0x10` length with r13 and
     calls `bcmp`, and ends without a match.

   The count is `mov rax,[rax+0x10] ; imul rbx,rax,0x38 ; mov [rsp+0x58],rax` (a
   `Vec` length with 0x38-byte elements). At 0x34221af:
   ```
   mov rax,[rsp+0x30] ; test rax,rax ; js neg ; add rax,rax ; ... ; add rax,3
   mov r14,-1 ; cmovae r14,rax
   neg: mov rax,-1 ; jmp 0x34221c0        (rejoins after `add rax,rax`)
   3 × { 20-byte compare of [r12] with rip data ; je 0x3422280 }
   cmp [rsp+0x58],r14 ; jae 0x342235a     → mov word [r15],0x57 ; mov [r15+8],r14
   ```
   - `[rsp+0x30]` holds the sixth argument (r9). No instruction on the two paths from the
     entry to 0x34221af writes it. The only other write, at 0x34220db, is on the
     name-replace path, which leaves through `jmp 0x34222f8`.
   - Emulating the decoded block gives `limit(t) = 3 + 2t` for `t ≥ 0`.
   - The result saturates to `2^64 − 1` on carry (`t = 2^63 − 1`).
   - Every negative t also gives `2^64 − 1`, i.e. no cap.
   - The three bypass addresses (20 bytes each, at 0x59c0a8, 0x59c0bc and 0x59c0d0) are
     `0x677d831aef5328190852e24f13c46cac05f984e7`,
     `0x3c83a5cae32a05e88ca6a0350edb540194851a76` and
     `0x4dbf394da4b348b88e8090d22051af83e4cbaef4`.
   - When `count ≥ limit`, error tag **87** carries the limit at `+8`.
6. Callers:
   - Exactly three `call [rip→0x5774dc0]` exist: 0x2767925, 0x4d9a7e5 and 0x4d9b425. Each
     lies in its own FDE (`callers.tsv`).
   - Each is preceded by `lea r8,[rsp+0xc0]`.
   - Each is followed by `cmp word [rsp+0x60],0x186`. That is 390, the first tag past the
     390-entry error table, i.e. the `Ok` niche.
   - All three contain the same tier block (only the rel32 of the preceding direct call
     differs):
   ```
   call <equity>(r15, rbx) ; cmp rax,0x989680 ; jae big ; xor r9d,r9d ; jmp join
   big: movabs rcx,0xdbe6fecebdedd5bf ; mul rcx ; shr rdx,0x21
        cmp rdx,0x28 ; mov r9d,0x28 ; cmovb r9,rdx ; add r9,0xa
   ```
   - The multiply-high magic with shift 97 is exactly `⌊x / 10^10⌋` for every u64 x. The
     tool proves this with the Granlund–Montgomery error bound, not by sampling.
   - So the tier is 0 below 10,000,000, and `10 + min(x / 10^10, 40)` otherwise.
   - Each copy also has one `mov r9d,0xa` reached from a list-membership loop (fixed
     tier 10).

### Reference claims tested

| can1357 claim | bytes | verdict |
|---|---|---|
| `ERR_EXTRA_AGENT_INVALID_NAME = 83`, `OK = 390` | Display arm index 83; Ok niche 0x186 in all 3 callers; 390 table entries | confirmed |
| `name.is_empty() \|\| name.len() > 16` | `lea/cmp/ja` admits exactly 1..=16 of the String's third (length) word | confirmed; byte length |
| `BASE_EXTRA_AGENT_LIMIT = 3`, `2 * tier + 3` (marked `[INFERENCE]`) | `add rax,rax ; add rax,3`, saturating | confirmed |
| negative tier → `usize::MAX` | `js` → `rax = −1`, carry → `r14 = −1` | confirmed |
| `ERR_TOO_MANY_EXTRA_AGENTS = 87` | `mov word [r15],0x57` after `jae` | confirmed; payload `[+8] = limit` not in reference |
| three `EXTRA_AGENT_CAP_BYPASS` addresses | 3 × 20-byte rip data compares | confirmed, same bytes |
| equity gate `10_000_000`, step `10_000_000_000`, `10 + min(q, 40)` | gate imm, exact magic divisor, clamp 0x28, offset 0xa | confirmed in all 3 copies |
| `0x2766F70` dispatches into extra-agent save | first caller FDE starts at 0x2766f70 | confirmed for this one call edge |

## Implementation and comparison

Not yet implemented. No Rust path exists in this packet. The predicates to implement are
`(1..=16).contains(&name.len())` (byte length), `limit = 3usize.saturating_add(2 *
tier)` with `tier < 0 ⇒ usize::MAX`, and the tier formula above.

Corruption controls in `tests/test_extra_agent_admission.py`:
- a truncated buffer and one flipped message byte are rejected (SHA-256 mismatch);
- changing the tag store immediate to 84 fails closed, because no constructor is found
  (structural path, digest bypassed);
- `jbe` or `jb` in place of `ja`, or the length load rewritten as a store, no longer
  decodes as the guard;
- shifting k or c by one, or swapping `ja` for `jae`, changes the admitted interval;
- a cap `add` of 4 instead of 3 disagrees with the formula;
- a perturbed magic is rejected as a divisor, and shift + 1 yields 2·10^10, not 10^10;
- `Image.read(0x10)` and `Fdes.range_of(0x1000)` raise;
- a fresh `--out` run is byte-identical to the packet files.

## Results and limitations

| metric | value |
|---|---|
| message LEA references | 1 / 1 |
| error Display table entries / tags reaching the message arm | 390 / [83] |
| `mov word [..],83` stores in `.text` | 1 |
| admitted name lengths (bytes) | 1..=16 (16 / 2^64 values) |
| GOT slots holding the save function / indirect callers | 1 / 3 |
| callers whose Ok tag equals the table size | 3 / 3 |
| distinct caller tier forms | 1 |
| cap formula vs reference over 9 boundary tiers | 9 / 9 equal |

Inferences, not proved by bytes:
- The function is the extra-agent save and the sixth argument is a quota tier.
- The direct call before the tier block returns account equity in raw units. 10^7 and
  10^10 would be $10 and $10,000 at 6 decimals, but the unit is not established.
- The fixed-tier-10 branch is the reference's `is_foundation_self_signer`.

Unresolved:
- The `None`-niche test and the `rsp+0xc0` copy in the callers were read manually and
  are not tool-checked.
- Any trimming or normalisation of the name before the call is not examined.
- Indirect references to the message and other stores of tag 83 (for example through a
  register) are not searched.
- Only the three GOT-slot calls are covered. A direct `call 0x3421e20` would be missed;
  the tool found none in a manual scan.

No progress gate is requested. The packet is evidence only.

Next question: what does the direct call before the tier block (0x275fee0 in the first
copy) return? Which state field and unit is it, and which list does the fixed-tier-10
loop scan?
