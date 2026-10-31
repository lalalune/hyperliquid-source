# consensus: node #94 `node/consensus/config.rs` validator checks (wallet walk 30:17, public IP 44:25 / 51:21 only when `static+0x8f2` is set, node_ips 60:13; a second address set skips both later checks; node IP tag 1 = LocalNode)

Question: what does the consensus config builder `0x284a5a0` check before it
returns? The can1357 lead (`node/consensus/config.rs`) says it "walks the
`StaticConfig.node_ips` BTree tree at `static_config + 0xA48`, and panics if
the validator address is absent", using `node_ips.get(&home_validator)` and
the error "validator is not in node_ips". Then, when `static_config + 0x8F2`
is set, it compares the configured node IP with the discovered public IPv4
address and panics on a mismatch. On an error fetching the IP it "keeps
building the config after logging" (`0x284A990..0x284AA67`). It decodes the
node-IP tag as `Ip` = 0, `Error` = 1, `LocalNode` = 2. What do the bytes show?

- Component ID: `consensus` (`docs/COMPONENTS.md`; path rule
  `node/consensus/*`). `research/catalogue/seed-candidates.json` lists the
  `node/consensus/config.rs` seeds `0x284a5a0` ... `0x284b660`. No earlier
  packet or open PR covers this function.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for claims to test; no code, comments or names copied.
- Claim status: byte-level facts are observations; inferences are marked as
  such, and open questions are listed under Unresolved. This is partial
  `consensus` research; no gate changes.
- Scope (9 windows):
  - five windows of the builder FDE `0x284a5a0..0x284b1da`:
    `0x284a5a0..0x284ae05`, `0x284ae13..0x284ae7c`, and the panic and
    second-set-miss tail `0x284afbf..0x284b0f1`;
  - the node IP Debug formatter `0x284b660` up to its two arms;
  - the whole `&str` Display `0x21b7390`, `String` Display `0x288bb90` and
    `AddrParseError` Display `0x157d4b0`.
  - Also: the path string, all five config.rs Locations, the four format
    templates, the message prefix, the RELATIVE and `memcmp` GLOB_DAT slots,
    and a whole-`.text` census of references to the Locations.
- Excluded:
  - what the second set (`0x3bb4f30`) and the third map (`0x45c3d20`)
    contain;
  - the public IP helper `0x13ca370`;
  - `0x258ad80`, the rest of the builder, and the
    seeds `0x284b1e0`, `0x284b430`, `0x284b550`.

## Reproduce

```sh
make verify
python3 tools/consensus_config_static.py --json > research/work-items/consensus-config-94/records.json
python3 -m unittest tests.test_consensus_config_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`), the `.rela.dyn`
`R_X86_64_RELATIVE` entries, and the `GLOB_DAT` entries with their `.dynsym`
names. It never executes the target. It needs only Python 3 (run here with
3.14.7 on macOS arm64; about 1 s). `records.json` is its complete output, and
the test suite regenerates it and compares the two.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has 9
windows (552 instructions, 2877 bytes), one for each checked byte window. All
181 `records.json` VAs that fall inside a window are instruction starts
there. The tool refuses unless each of the 132 decoded call, branch and
RIP-relative operands, and every instruction it checks, lies inside a checked
window.

## Evidence

### Strings and Locations (observation)

The file holds `/node/src/consensus/config.rs` once, inside
`/home/ubuntu/hl/code_Mainnet/node/src/consensus/config.rs` at `0x1e03e0`.
Exactly five RELATIVE-backed Locations point at it. No RELATIVE slot holds
any of them. The census covers every disp32 in `.text` that follows a
RIP-relative ModRM byte. It finds five references, all REX.W `lea`, one per
Location, all in the builder:

| Location | Line:column | Referenced at | Use |
| --- | --- | --- | --- |
| `0x56c53d0` | 30:17 | `0x284b07d` | panic, template `0x1dedcc` |
| `0x56c5370` | 44:25 | `0x284abd8` | panic, template `0x1ebedd` |
| `0x56c5388` | 51:21 | `0x284ac96` | log call through slot `0x576e978` (`0x143d010`), template `0x1f41c9` |
| `0x56c53a0` | 60:13 | `0x284b0da` | panic, template `0x20210b` |
| `0x56c53b8` | 71:32 | `0x284ae41` | last (pushed) argument of `0x258ad80` |

The three panics call slot `0x576e098` (`0x157b810`). The templates decode
as:

- `0x1dedcc`: `{}: running with wallet that is not a validator, address={}`
- `0x1ebedd`: `{}: public_ip does not match abci state. public_ip={} abci_node_ip={}`
- `0x1f41c9`: `could not get public ip, not validating against abci state: {} @@ [public_ip: {}] @ [abci_node_ip: {}]`
- `0x20210b`: `{}: validator is not in node_ips: {}`

The first argument of each panic is the str at `0x56c5360` (RELATIVE pointer
`0x3f4813`, length 19): `CONFIGURATION ERROR`. It is formatted by
`0x21b7390`, which passes the pointer and length to the str formatter.

### Check 1: the wallet must be in the `static+0xa48` tree (observation)

- `r15` is the signer (`rdx`). The 20 wallet bytes are `[r15+0x80]` (16)
  and `[r15+0x90]` (4).
- `rsi` is the static config, kept in `r14`. The root is
  `[static+0xa48]`, the height `[static+0xa50]`, the item count
  `[static+0xa58]`. A zero root or count jumps to the 30:17 panic at
  `0x284b039`.
- `cl` starts at 2. The loop takes one item per `dec rax` and leaves at
  `0x284a842` once all `count` items are seen. For an item, it compares
  `item+0x38..+0x4c` (20 bytes, with `item = node + 8 + 0x58 * index`) with the
  wallet. When they differ it goes on with the next item (`0x284a7ff`). When
  equal it copies the byte at `item+0x4c` to `cl`, the u32 at `item+0x4d` to
  `edx`, and the item's 20 bytes to `rsp+0x50`. It then jumps back into the
  loop (`0x284a827`), not out of it.
- After the loop, `cl == 2` jumps to the 30:17 panic. Otherwise the tag goes
  to `[rsp+3]` and the u32 to `[rsp+4]`.

So every item is visited and the last match wins. "No match" is the only
failure, and it is the 30:17 "running with wallet that is not a validator"
panic. Its address argument is `rsp+0xc0`, formatted through slot
`0x576f570` (`0x1444400`).

Inference: tag 2 here is the "not found" value of the same tag byte that the
Debug formatter below decodes.

### The second set (observation)

- `ebp` is the byte at `static+0x8f2` (the validate byte below). It is also
  stored to `[rsp+0x10]`.
- The code calls slot `0x57732e8` (`0x33de620`), then `0x3bb4f30` with an
  argument block that ends with `static+0x8f8`. It searches the result at
  `rsp+0x70` with `memcmp` (GLOB_DAT slot `0x576e488`) over 20-byte keys,
  using the address copied from the match.
- Found sets `bl = 0` (`0x284a9f1`). An empty tree (`0x284a92c`) or a miss
  below a leaf (`0x284a9d9` to `0x284afbf`) sets `bl = 1`.

### Check 2: public IP, only when the validate byte is set (observation)

- `test bpl, bpl; je 0x284acca`: with the byte clear, the IP step is skipped
  entirely: no fetch, no parse, no log.
- Otherwise the code calls slot `0x576e948` (`0x13ca370`). The String it
  returns ends up at `rsp+0x70` (pointer `+0x78`, length `+0x80`).
- It sets `al = 1`, and a length over 15 jumps to the log. Otherwise it calls
  `0x1573af0` with a `(pointer, length)` cursor. The result is accepted only
  if the cursor has no bytes left (`[rsp+0x208] == 0`) and the low byte of
  the result is set (`test dl, al`); then `eax` holds bits 8..40 of the
  result. Any failure
  jumps to the log with `al = 1`.
- `test bl, bl; je 0x284acb3`: a wallet in the second set skips the
  comparison.
- Otherwise `cmp byte [rsp+3], 0; jne` goes to the panic, and
  `cmp [rsp+4], eax; je` goes to `0x284acb3`. So the comparison passes only
  for tag 0 with an equal u32.
- The 44:25 panic's arguments are: the prefix; the fetched String
  (`rsp+0x70`, by `0x288bb90`, which passes `+0x8` / `+0x10` to the str
  formatter); and the node IP at `rsp+3` (by `0x284b660`).
- The 51:21 log stores `al` at `rsp+0x120` and formats it through slot
  `0x5770708` (`0x157d4b0`). Its other two arguments are the String and the
  node IP (through `0x26ab530` and `0x26aa760`, not read here). It then falls
  through to `0x284acb3`. That code passes the String's capacity and pointer
  to slot `0x576e010` (a deallocation, by inference) and goes on to the next
  check.

`0x157d4b0` indexes a length table at `0x25d7f8` and a RELATIVE pointer table
at `0x5674c48` by the byte. Entry 1 is `invalid IPv4 address syntax` (27
bytes), and entry 0 is `invalid IP address syntax`.

Inference: this is std `Ipv4Addr::parse_ascii` inlined. std rejects input
over 15 bytes before parsing, and requires the parser to consume all input.
Its error is `AddrParseError(AddrKind::Ipv4)`, and the byte 1 is that kind.
So any helper output that is not exactly a dotted IPv4 address is logged, not
compared. If the helper keeps a trailing newline, that case also lands here;
whether it does is not checked.

### Check 3: node_ips (observation)

- The code calls slot `0x5773b48` (`0x45c3d20`). Its arguments are:
  `rdi = rsp+0x70`, `esi =` the validate byte, `rdx = static+0x8f8`, and
  `rcx` pointing to the byte 1 followed by the 20 matched address bytes.
- `test bl, bl; je 0x284ae05`: a wallet in the second set skips this check.
- Otherwise it searches `rsp+0x70` with `memcmp` over 20-byte keys at
  `node+8`. The value cursor starts at `node+0xe3` and moves 5 bytes per key,
  so a match at index i reads the byte at `node+0xe8+5i`.
- An empty map (`0x284ad30`), a miss below a leaf (`0x284add3`), or a value
  byte of 2 (`0x284adff`) all reach the 60:13 panic "validator is not in
  node_ips". Its address is `rsp+0x30`, formatted through slot `0x5775088`
  (`0x4c7b1e0`).

Then `0x258ad80` is called with `rsi = rsp+0x70` (the same map), `rdx` =
the str `node_ips` (`0x20a778`, `ecx = 8`), and Location 71:32 pushed as
its last argument.

Inference: the 5-byte value is an `Option` of the node-IP enum, with 2 as
`None`. 71:32 is a `#[track_caller]` Location; the work `0x258ad80` does with
the map is not read here.

### The node IP Debug formatter `0x284b660` (observation)

`cmp byte [rdi], 1; jne`. Tag 1 writes `LocalNode` (`0x3f482d`, 9 bytes),
then formats the field at `+1` with `0x21b6940`. Every other tag writes `Ip`
(`0x3f482b`, 2 bytes), then formats the field with `0x28e8b50`. There is no
third arm.

Inference: the enum has two variants, `Ip` = 0 and `LocalNode` = 1, each
with a 4-byte field. `Ip`'s field is the value compared with the parsed
IPv4 address.

## Lead check

| Lead claim | Binary |
| --- | --- |
| A wallet absent from `static + 0xA48` panics "validator is not in node_ips" | That case is the 30:17 panic "running with wallet that is not a validator". "validator is not in node_ips" is a separate 60:13 check on another map built later |
| `node_ips.get(&home_validator)` | A walk of every item that compares `item+0x38..+0x4c`; the last match wins |
| IP check when `+0x8F2` is set | Yes. With the byte clear there is no fetch, parse or log at all; the lead takes the fetch result as an input and handles its error whatever the flag |
| Non-`Ip` tag is a mismatch | Yes: tag != 0 panics |
| Logs and continues when the IP is unavailable (`0x284A990..0x284AA67`) | It logs and continues on an IPv4 parse error. The log is `0x284abf2..0x284acb3`; `0x284a990..0x284aa67` is the second-set lookup |
| No exemption | A wallet in the second set skips both the IP comparison and the node_ips check |
| `Ip` = 0, `Error` = 1, `LocalNode` = 2 | The Debug formatter has `LocalNode` = 1 and `Ip` for everything else; 2 is the "absent" value in both lookups |
| `abci_node_ip` printed as `Ip(ip)` Display | Printed by the derived-style Debug `0x284b660`; `public_ip` is the fetched String, not the parsed address |

## Models

The tests run `build` (the binary's checks) and `lead_build` (the lead's) on
the same inputs:

- the last of two matching items decides the comparison;
- a LocalNode tag panics at 44:25;
- with the validate byte clear, a different public IP passes;
- `10.0.0.1\n`, a 15-byte zero-padded address and `not-an-ip` log at 51:21;
- the second set skips both later checks;
- a missing node_ips entry, or one with tag 2, panics at 60:13.

The lead reports a missing wallet as "validator is not in node_ips" and tag 1
as `Error`.

## Unresolved

- The contents of the second set (`0x33de620`, `0x3bb4f30`) and of the third
  map (`0x45c3d20`). Neither is named in the binary.
- What `0x13ca370` returns. The disassembly references
  `{}/override_public_ip_address`, `curl -s {}` and the host names
  `ifconfig.me`, `api.ipify.org`, `icanhazip.com`, but none of this is
  checked by the tool.
- The field formatter `0x28e8b50`, which jumps through slot `0x576f6d0`
  (`0x157c730`).
- The log field formatters `0x26ab530` and `0x26aa760`.
- `0x258ad80`, the rest of the builder, and the seeds `0x284b1e0`,
  `0x284b430` and `0x284b550`.

## Controls

`tests/test_consensus_config_static.py`: 33 tests. The 19 corruption tests
reject:

- changed window bytes, and an operand outside every window;
- re-pinned rewrites: a first-match loop exit, a different sentinel tag, the
  validate byte offset, the skip branch, the 15-byte limit, the tag
  comparison, the second-set branch, the node_ips value tag, the Debug arm,
  and the 71:32 `lea`;
- a stray `lea` to a config.rs Location planted in int3 padding;
- a moved Location path pointer or prefix pointer, a template byte, a
  variant name, the fetch slot, and the `AddrParseError` text.
