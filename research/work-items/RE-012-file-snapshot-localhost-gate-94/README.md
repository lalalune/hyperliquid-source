# RE-012: what does the `fileSnapshot` admission rule actually compare?

- Component ID: `info-api` (path rule `info_server/*`), with the gate living in the
  `abci_state_info_handler.rs` request future rather than `handle_request.rs`.
- Target release and full SHA-256: node **#94**, 91,774,280 bytes,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`; drift check on
  node **#115**, 105,896,032 bytes,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: hyperliquid-source `main` `3324e503`; can1357-hl
  `999556f6e0a474b8312db96ec3149e1c44e97c23` (lead only; no code copied).
- Claim status: **observation** for every byte, address, constant, relocation and
  Location cited below; **inference** for the Rust-level names (`IpAddr`, `String`,
  `Poll`, "critical logger"); **unresolved** for the semantics of the two result
  encodings and for where the `IpAddr` input is derived (`user_ip.rs`).
- Scope included: the `fileSnapshot` arm of the request future in both captures, its
  three admission checks, the reject log call and its Location, the Display thunk
  the log uses, the boxed inner future hand-off, the dispatch tables and the vtable
  slot that names the future.
- Scope excluded: the other 50+ request arms, the inner `file_snapshot` future and
  the snapshot write itself, the HTTP layer that produces the client `IpAddr`, any
  runtime behaviour, and any component gate. No gate is requested.

## Why this packet

RE-012-info-request-path established that FDE `0x27e91d0` owns the template
`not writing snapshot to file because request was not from localhost: ` and called the
write path "gated on a localhost request check". It did not say what the check
compares. The reference reconstruction writes `client_addr.ip().is_loopback()`
(`handle_request.rs:80`), which accepts all of `127.0.0.0/8`. The captured bytes do
something narrower, and they add a bound the reference does not have.

## Result

Both captures apply the same three rules, in this order, before the snapshot future
is built:

| Rule | #94 instruction (VA) | #115 instruction (VA) |
| --- | --- | --- |
| `IpAddr` tag byte == 0 (V4)? | `80 bb 94 00 00 00 00` at `0x27e9295` | `80 bb b4 00 00 00 00` at `0x29739b7` |
| V4: 4 octets == `127.0.0.1` exactly | `81 bb 95 00 00 00 7f 00 00 01` at `0x27ec599` | `81 bb b5 00 00 00 7f 00 00 01` at `0x2976aaf` |
| V6: 16 octets == `::1` | `pcmpeqb` vs `0x205c00` at `0x27e92aa`, mask `0xffff` | `pcmpeqb` vs `0x453120` at `0x29739cc`, mask `0xffff` |
| `out_path.len() < 0x65` (101) | `48 83 fd 65` / `jb` at `0x27e92cf` | `48 83 fa 65` / `jb` at `0x29739f3` |

- The IPv4 test is a **dword equality against `0x0100007f`** (bytes `7f 00 00 01`),
  i.e. exactly `127.0.0.1`. `Ipv4Addr::is_loopback` would test one byte against
  `0x7f`. A request from `127.0.0.2` is rejected by the captured node and accepted
  by the reference text.
- The IPv6 test compares all 16 octets with the constant `00…00 01` (`::1`), which
  coincides with `Ipv6Addr::is_loopback`.
- The length bound is new relative to the reference: when `out_path.len() >= 101`
  the `String` is freed (`call [0x576e010] -> 0x54c8cb0`, #115 `[0x64df4a0] ->
  0x635de30`) and a reject result is returned **without** the localhost log.
- A non-localhost address is logged through the critical logger (`0x143d010`, #115
  `0x150b310`; both reference `base/src/crit_msg.rs`) with the `IpAddr` formatted by
  a 23-byte thunk (`0x157c690`, #115 `0x1687690`) that dispatches on tag byte == 1 to
  the V6 formatter and otherwise to the V4 formatter. The log Location is
  `abci_state_info_handler.rs:153:21` in #94 and `:156:21` in #115.
- `fileSnapshot` is index 0 of the request jump table (`0x3f0c80`, #115 `0x600060`),
  consistent with it being the first declared variant. #115 computes the index with a
  niche on the first qword (`cap + i64::MIN + 1` masked by the sign), #94 reads a
  plain discriminant byte at `+0x50`.
- The future carries a 17-byte `IpAddr` copied from the input (`+0x80..+0x91` to
  `+0x94..+0xa5` in #94; `+0xa0..+0xb1` to `+0xb4..+0xc5` in #115): a one-byte tag
  followed by 16 octet bytes. It is an `IpAddr`, not a `SocketAddr`; no port is
  carried into the gate.
- The reject log is **not** followed by any file write; the accept path boxes a
  `0x58`-byte inner future (`call 0x27f0d50`, `mov edi,0x58`) and loads its `dyn Future`
  vtable from `0x56c3d98`. The vtable layout is bound from the captured bytes: slot 0
  (`0x56c3d98`) is `drop_in_place` at `0x2833ed0`, slot 1 is the size `0x58` (matching the
  allocation), slot 2 the alignment `8`, and slot 3 (`0x56c3db0`) is `poll` at `0x27f45d0`.
  Both function slots are RELATIVE relocations to FDE starts. The box helper itself calls
  `0x2833ed0`, consistent with a drop on its cleanup path. Pinned for #94 only.

## Reproduce

Working directory: repository root. Linux x86-64, Python 3.12.3, GNU objdump 2.42.
Static parsing only; no captured binary was executed.

```sh
make verify catalogue-check doctor
python3 -I tools/file_snapshot_localhost_gate.py --check
python3 -m unittest discover -s tests -p test_file_snapshot_localhost_gate.py -v
python3 -m unittest discover -s tests -p test_info_request_path.py -v
```

The tool verifies both artifact digests against `provenance/artifacts.json`, then
fails closed on: a template that is not unique, a template with other than one
`.text` LEA, an owning FDE other than the stated one, a vtable slot that does not
name that FDE, any anchored instruction whose bytes differ, any RIP-relative target,
GOT slot or RELATIVE addend that differs, a 16-byte `pcmpeqb` operand that is not
`::1`, a Location record other than the stated file/line/column, a logger FDE with
no reference to `base/src/crit_msg.rs`, or a jump table without the stated entry.
`--check` requires byte-identical regeneration of `file-snapshot-localhost-gate.json`.

Raw exports (`objdump -d -M intel`, raw bytes shown) and the GNU frame lines are
kept under `objdump/` and `frames.txt`; `MANIFEST.sha256` covers every packet file.

## Negative controls (in the test)

| Mutation | Result |
| --- | --- |
| dword operand `7f 00 00 01` → `7f 00 00 02` (both captures) | `EvidenceError` |
| last byte of the `::1` constant → `0x02` | `EvidenceError` |
| length bound `0x65` → `0x66` | `EvidenceError` |
| template LEA displacement zeroed | `EvidenceError` (template has 0 LEA sites) |

Each control mutates an in-memory copy and runs the same `analyze` path; the
on-disk captures are never modified.

## Coordinates

All addresses are linked ELF virtual addresses. In #94 `.text` has
file offset = VA − `0x1000`, `.rodata` has VA == file offset, `.data.rel.ro` has
file offset = VA − `0x2000`. In #115 `.text` is VA − `0x1000`, `.rodata` VA == offset,
`.data.rel.ro` VA − `0x2000`. Instruction-start addresses include prefixes.

Function bounds, from `.eh_frame_hdr` (tool) and `objdump --dwarf=frames`
(`frames.txt`):

| Role | #94 | #115 |
| --- | --- | --- |
| request future `poll` | `0x27e91d0..0x27ecdc2` (15,346 B) | `0x29738e0..0x2977559` (15,481 B) |
| vtable slot → that future | `0x56c39b0` | `0x6441e98` |
| `IpAddr` Display thunk | `0x157c690..0x157c6a7` | `0x1687690..0x16876a7` |
| critical logger | `0x143d010..0x143e888` | `0x150b310..0x150baaf` |
| box inner future | `0x27f0d50..0x27f0df5` | not pinned |

## Limitations and next question

- The two reject results differ in shape (#94: `[r14] = 2, [r14+8] = 0` after the
  log; `[r14] = 0x35, [r14+8] = 0x143` plus the length after the bound). Their
  enum meanings are not resolved here; a second `cmp …,0x65` at `0x27eb7ba` shares
  the `0x143` tail from another arm and is outside this packet's scope.
- Which address the HTTP layer hands to this gate (TCP peer vs. a header) is not
  established. `.rodata` of #94 contains no `x-forwarded-for`, `x-real-ip` or
  `forwarded` string outside the h2 static header table, which is a negative
  observation, not a proof. The hub `0x24af210` owns `user_ip.rs:28:48` only as a
  panic Location.
- No Rust reconstruction, execution, equivalence or gate is claimed.
- Next question: bind the inner `file_snapshot` future (its `poll` at `0x27f45d0`, slot 3 of
  the `0x56c3d98` vtable; `0x2833ed0` is that vtable's `drop_in_place`) to
  the `outPath` write and the `includeHeightInOutput` flag, and locate the call that
  produces the 17-byte `IpAddr` for this request.
