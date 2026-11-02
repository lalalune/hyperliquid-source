# RE-010: bind gossipPriorityBid from wire to handler in node #94

- Component ID: RE-010 (action dispatch and handlers), with RE-005 for the wire shape
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `0f42105affd11c8b47c9de2613264d84dd26103b`; `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` was not used; RE-004 found no rule for this action there
- Claim status: observation for the bytes, offsets, order, statuses, call graph and the runs of the real instructions; inference where marked; unresolved items are listed under limits
- Scope included: the dispatch arms for case 81, the wrapper `0x1e60bb0`, the map arm of decoder `0x3b6c630`, serializer `0x1e971d0`, the gates inlined in `0x4c8c0a0` and `0x4c8c3f0`
- Scope excluded: the array arm of the decoder (`0x3b6c8f6`), the other three serializers, the other field matchers, the handler body and the charge, which `RE-004-gossip-bid-gates-94` covers with stubs

## Question and gap

`RE-010-dispatch-cases-76-87` stops case 81 at "arm, first call" and finds no anchor in the
callee. `RE-004-gossip-bid-gates-94` recovers `0x2727bc0` but leaves these open: that this
handler belongs to `gossipPriorityBid`, that `r8` is `slotId` and `r9` means `maxGas` is
set, what bounds the caller applies, why the first stored IP byte is 0, and what happens
to text after the last parsed digit. Which function fills those arguments?

## Reproduce

From the repository root:

```sh
python3 -I -B research/work-items/RE-010-gossip-priority-bid-path-94/verify.py
python3 -m unittest tests.test_gossip_bid_path
rustc --edition 2021 --test src/node94-gossip-bid-admission/lib.rs -o work/gossip-bid-admission
work/gossip-bid-admission
```

`verify.py` uses the standard library, imports nothing from this repository, needs the LFS
target and takes about two seconds. It rereads the retained exports, so it does not need
objdump. `export_disassembly.sh` regenerated those exports with GNU objdump 2.47.20260726
(Homebrew binutils) and Apple LLVM objdump 21.0.0, on macOS arm64. The target is never run.

## Evidence

Coordinates are virtual addresses. `gnu.txt` and `llvm.txt` hold 26 spans and 609
instructions; `verify.py` requires equal boundaries and mnemonics in both, and requires
every raw byte to equal the ELF. 71 pinned instructions, the literals, three status
Display arms, the field table, three dispatch table entries and nine FDE extents are
rechecked from bytes.

### Path

```
serde content
  -> decoder 0x3b6c630          fills a 0x30-byte payload
  -> 0x3357679, 0x335b720       store it at enum +8 and tag 0xc5 at enum +0
  -> dispatcher case 81         [r12] - 0x74 = 81; passes payload, user, state
  -> wrapper 0x1e60bb0          this packet's gates
  -> handler 0x2727bc0          RE-004 gates and charge
```

Reference census over all of `.text`: one `call` to the wrapper (`0x2759888`) and one to the
handler (`0x1e60c87`). A byte scan for `E8`/`E9` targets and RIP-relative `lea` finds no
other reference, and no `.rela.dyn` addend names either address.

### Payload layout

Bound by the decoder's stores (`0x3b6cc58..0x3b6cc79`), the serializer's key literals and the
wrapper's reads, which agree.

| Offset | Field | Serializer evidence | Wrapper read |
|---|---|---|---|
| `+0x00` | `maxGas` Option tag | `cmp dword [r15],1` at `0x1e97369` | `r14`, then bit 0 only |
| `+0x08` | `maxGas` value | `0x1e9736f`, key `maxGas` | `rbp` |
| `+0x10` | `ip` capacity | not read | not read |
| `+0x18` | `ip` pointer | `0x1e9730a`, key `ip` | `0x1e60c44` |
| `+0x20` | `ip` length | `0x1e9730e` | `0x1e60c29` |
| `+0x28` | `slotId` | `0x1e972a9`, key `slotId` | `0x1e60bcb` |

### Wire shape

- Named form: header byte `0x84`, written at `0x1e971f9` and read as a msgpack fixmap of four. Keys in order: `type` (value `gossipPriorityBid`, passed by `0x2824235`), `slotId`, `ip`, `maxGas`.
- `maxGas: None` is written as `0xc0`, msgpack nil, at `0x1e973cb`; the key stays.
- Decoding the map form: `slotId` and `ip` are required, with `missing field` errors at `0x3b6cac1` and `0x3b6ca5e`. `maxGas` may be absent: `r14` starts at the unset marker 2 (`0x3b6c6b6`), which `0x3b6cc54` turns into tag 0.
- A repeated key reaches the duplicate-field path `0x3b6ca0a` with that key's name: `slotId` from `0x3b6c705`, `maxGas` from `0x3b6c7e9`, `ip` from `0x3b6c876`.

### Wrapper

`rdi` output, `rsi` payload, `rdx` user (20 bytes), `rcx` state. Tests run in this order:

| # | Condition | Output tag | Status, text | Word at `+0x10` |
|---|---|---|---|---|
| 1 | `slotId >= 0x0ccccccccccccccc` | `0xe` | `0x13f` `Invalid input number` | `slotId` |
| 2 | `maxGas` set and `>= 0x0ccccccccccccccc` | `0xe` | `0x13f` `Invalid input number` | constant `1`; `+0xa..+0x10` zeroed |
| 3 | `ip` length `>= 16` | `0xe` | `0x143` `Invalid input length` | not written |
| 4 | parser fails, or bytes remain | `0xe` | `0xb9` `Failed to parse ip` | not written |
| 5 | handler returns `0x186` | `0xd` | none | not written |
| 6 | handler returns anything else | `0xe` | that status | whole `0x60`-byte result copied to `+8` |

Row 3 runs before the parser, so a long text never reaches it. Rows 1 and 2 come first, so
a bad number hides a bad IP. On rows 5 and 6 the handler receives:

| Handler input | Source |
|---|---|
| `rdi` | wrapper `rsp+8`, a `0x60`-byte result |
| `rsi` | state |
| `rdx` | user |
| `rcx` | parser word with its low byte cleared by `and rax,~0xff` at `0x1e60c69` |
| `r8` | `slotId` |
| `r9` | `maxGas` Option tag |
| stack word | `maxGas` value, read back by the price compare at `0x2727ca4` as `[rsp+0x160]` |

For `None` the decoder sets no wire value at `+8`. The wrapper masks that word with the tag at `0x1e60be6`, and RE-004 step 5 gates the handler's compare on the flag.

This settles the RE-004 limits above. `r8`, `r9` and the stack word are now observed. The
first stored IP byte is 0 because this wrapper clears it. Trailing text is refused here, as
`0xb9`, not left to the handler. Handler gates `0x181`, `0x182`, `0x178` and `0x179` are
unchanged.

### The three copies

The binary has three dispatchers, and each has its own case 81 (`0x3ede28`, `0x712dfc`,
`0x712f5c`). The other two copies of the handler's status writes sit in `0x4c8c0a0` and
`0x4c8c3f0`, the functions RE-004 left out, called from `0x4d83687` and `0x4d847a7`. Each
inlines these gates with the same order, bound, offsets and statuses, including the
constant `1`, then stores `0xb9` for a failed parse. Register order is the same; those arms
pass `r13` for the user where this arm passes a 20-byte stack copy. Only the gate prefix
of those copies is checked here.

## Inferences

- The wrapper's length gate plus the parser look like an application length check followed by an inlined `Ipv4Addr::from_str`. Nothing in the bytes names that source.
- The constant `1` is a compiled fact with no recovered reason. It may reflect how the original built this error, since `Invalid input number` prints no value. It is not read as a defect.
- `0x0ccccccccccccccc` is the shared `Invalid input number` bound seen in other packets (for example `RE-004-hip3-liquidator-amount-gate-94`). It equals `i64::MAX / 10`; no meaning for it is recovered here.
- Bit 0 of `r9` is the only tested bit; the decoder only produces 0 or 1, so the tag reading is firm for decoded actions.

## Implementation and comparison

`src/node94-gossip-bid-admission/` is independently authored `no_std` Rust built with direct
`rustc 1.94.1`, edition 2021, no dependencies. It reconstructs the gates only. No compiled
bytes are compared, and no window is registered in `research/byte-windows.json`.

`vectors.tsv` holds the target's output for 1,568 cases, the product of 7 slot, 7 gas, 16 IP
and 2 handler values, with both ends of the bound. They come from running the real arm and
wrapper instruction list in `verify.py`'s interpreter. The parser and handler are stubs:
the parser stub applies the published RE-004 rule, and the handler stub records its inputs
and writes a marked result. Volatile registers are scrambled across each stub, and the
stack and callee-saved registers must balance. A separate rule list in the same file has to
predict every output byte and event. The Rust tests replay every vector.

## Results and limitations

| Measure | Result |
|---|---|
| Spec agreement over real wrapper instructions | 1,568/1,568 |
| Outcomes | `0x13f` 1,056; `0x143` 128; `0xb9` 256; handler reached 128 (64 ok, 64 failing) |
| Instruction-level text mutants killed | 36/36 |
| One-byte corruptions of wrapper instructions rejected | 85/85 |
| GNU and LLVM agreement | 609/609 instructions |
| Rust vector replay | 1,568/1,568, 3/3 tests |
| Rust mutants killed, run once by hand, not retained | 7/7 |

`results.json` holds the retained metrics. Mutants are applied to instruction text because
the interpreter reads the authenticated export; corruption of the bytes themselves is
caught by the byte check. An early mutant survived until the fixture gave `ip` a capacity
different from its length, so that offset is now distinguished.

Limits:

- The interpreter models only the instructions in these two spans, and its semantics are my own. It is a check of the listed behaviour, not an emulator of record.
- Stubbing the parser means parser behaviour is RE-004's result. The Rust parser is compared only on this packet's 16 IP strings.
- `ip` is UTF-8 text in the target; non-ASCII input is not exercised.
- The census is a byte-pattern superset for direct and RIP-relative references plus `.rela.dyn`. It does not rule out a pointer computed at run time.
- Stale output bytes on rows 1, 3 and 4 are left as found; nothing here shows whether any consumer reads them.
- The array decoder arm, other serializers and other field matchers are unread, so the claim about required fields applies to the map form only.
- No gate changes. The charge core remains unread.

Next question: does the array arm at `0x3b6c8f6` accept a two-element form that omits `maxGas`, and does `0x26c79d0` refund a slot's previous bidder?
