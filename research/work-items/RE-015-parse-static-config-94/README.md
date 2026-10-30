# RE-015: parse_static_config_aws_name, release 94

- Component ID: global_constants / static_config
- Target release and full SHA-256: node 94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (91,774,280 bytes, BuildID `29a7b9d6c31d0c687c376a834eba4f3ddaac660b`)
- Source commit / reference commit: hyperliquid-source
  `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference can1357-hl
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only as a comparison
  clue, never copied into an MIT implementation.
- Claim status: observation for the items in Evidence marked confirmed;
  inference for the call-chain mapping; unresolved for the items in
  Limitations. No gate is requested.
- Scope included: the parse path called from
  `read_static_config_aws_name`, the key comparison, the variant
  mapping, the externally-tagged null check, and the string escape
  mechanism.
- Scope excluded: releases 115 and visor, StaticConfig layout (already
  in the constants work-item), the serde AwsName visitor at
  0x13f4360/0x13f5980/0x13f6410, and any execution of the captured
  binary. This packet is static only.

## Reproduce

Exact commands, run on a Linux x86-64 VM with GNU objdump 2.x and
readelf, against a copy of the release 94 binary verified before use:

```text
curl -L -o /tmp/hl94/hl-node \
  https://media.githubusercontent.com/media/can1357/hl/999556f6e0a474b8312db96ec3149e1c44e97c23/bin/hl-node-mainnet-new
sha256sum /tmp/hl94/hl-node
# 3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f
gpg --verify /tmp/hl94/hl-node.asc /tmp/hl94/hl-node
# Good signature, fingerprint CF2C2EA3DC3E8F042A55FB6503254A9349F1820B
objdump -d --start-address=0x164d630 --stop-address=0x164d73e /tmp/hl94/hl-node
objdump -d --start-address=0x164e930 --stop-address=0x164f6af /tmp/hl94/hl-node
objdump -d --start-address=0x164b3d0 --stop-address=0x164b980 /tmp/hl94/hl-node
objdump -d --start-address=0x164e800 --stop-address=0x164e930 /tmp/hl94/hl-node
readelf --debug-dump=frames-interp /tmp/hl94/hl-node
```

The recovery URL above is the one recorded in
`provenance/artifacts.json` for `artifacts/node/94/hl-node`. The
binary was not executed, not loaded, and no network, chain, or
signing action was performed. Coordinate system: virtual addresses
as shown by objdump/readelf; `.text` file offset is VA minus 0x1000.

## Evidence

Call chain, all addresses are VAs:

- `read_static_config_aws_name` at 0x164fb80 calls 0x164d630 at
  0x164fca8. After the call it reads two bytes at stack 0x18/0x19
  (tag, discriminant) and, on the non-1 tag path, applies 0x20 at
  0x164fd8a-0x164fda9. See the constants work-item for that window.
- 0x164d630 has a decoded FDE range 0x164d630-0x164d73e (not an
  `.eh_frame_hdr` index bound). It sets up a cursor at rsp+0x08 and
  calls 0x164e930 at 0x164d677.
  File: `disassembly/parse_static_config_aws_name_164d630.txt`.
- 0x164e930 has a decoded FDE range 0x164e930-0x164f6af. It is the
  main JSON object parser for this path: it skips whitespace
  (bitmask 0x100002600 for 0x09, 0x0a, 0x0d, 0x20), dispatches on
  `{`, `[`, `"`, `:`, `,`, `}`, and tracks nesting depth in byte
  0x48 of its cursor.
  File: `disassembly/main_json_parser_164e930.txt`.

Confirmed, key comparison:

- At 0x164eae7-0x164eafa the parser first checks that the parsed
  key length is 8, then compares its 8 bytes against the 8 bytes at
  0x20a458. Those 8 bytes are `aws_name` (the following bytes in
  the same blob are `capacity`, which is a different field name and
  is not part of this comparison). A key of any other length or
  content does not take this path. This matches the reference
  behaviour "key must be exactly `aws_name`".

Confirmed, variant mapping:

- 0x164b3d0 is called from 0x164e930 at 0x164f0a3 and 0x164f17d,
  after the key match and after `:` is consumed. It parses a
  string value, or, on `{`, a variant string, and maps it through
  a jump table (0x264a88) to a discriminant byte written at
  output+1. The table entries in the retained window include
  0x00, 0x20 (NvTestnet, at 0x164b820), and 0x4b (75), covering
  the full 0-75 range already established for the 76-entry table.
  File: `disassembly/variant_mapper_164b3d0.txt`.

Confirmed, externally-tagged core form:

- On `{`, the mapper skips whitespace, parses a variant string,
  skips whitespace, requires `:` (0x164b513, compare 0x3a), then
  calls 0x164e800.
- 0x164e800 skips whitespace, then compares bytes in order:
  `n` (0x164e86d), `u` (0x164e897), `l` (0x164e8af), `l`
  (0x164e8c7). Any mismatch returns error code 9; all four
  matching returns success. That is exactly the `{"Variant": null}`
  form, with whitespace allowed between tokens.
  File: `disassembly/expect_null_164e800.txt`.

Divergence, escape handling (mechanism, not yet execution-proven):

- The static_config cluster (0x164a059-0x1650300) contains no
  simple `cmp $0x5c` reject branch for strings. String parsing
  instead reaches an internal decoder at 0x4ebf970 (FDE
  0x4ebf970-0x4ebfc06). Its scan loop at 0x4ebfd80 ends a string
  on `"` (0x22, at 0x4ebfdf3) and, on `\` (0x5c, at 0x4ebfdfc),
  calls an escape decoder at 0x4ebef70 instead of failing.
  File: `disassembly/string_scanner_4ebfd80.txt`.
- The reference hand-written parser rejects any backslash
  outright. The binary therefore does not implement that rule as
  written. The most discriminating input is
  `{"aws_name":"Nv\u0054estnet"}`: the reference returns None
  (backslash present); a standard decoder returns `NvTestnet`.
  This input is listed as a candidate divergence below, not as
  an execution-proven output difference, because the binary was
  not run in this packet.

Candidate divergence, externally-tagged with extra keys:

- The reference externally-tagged parser requires `}` immediately
  after `null`, so `{"aws_name":{"NvTestnet":null,"x":1}}` fails
  there. The binary mapper returns to the main object loop after
  a successful null check, which then parses `,` and the next
  key/value and only ends at `}`. Its mechanism is therefore
  more permissive for extra keys after an externally-tagged
  value. This is a mechanism difference, not an execution-proven
  output difference.

Not traced to a conclusion in this packet:

- Whether a second `aws_name` key overwrites or is ignored, and
  how trailing bytes after the closing `}` are treated by the
  wrapper at 0x164d630 (0x164d67c onwards, including the 0x164d6fa
  branch). Those branches were not followed to a conclusion and
  are not claimed either way.

## Implementation and comparison

Not yet implemented/measured. No Rust implementation, no
comparator, no fixture run, and no gate is claimed from this
packet. The table below is the reference-derived expectation
that a future comparator should test against, with the binary
mechanism notes above applied where they differ.

| Input | Reference parse | Binary mechanism note |
| --- | --- | --- |
| `"NvTestnet"` | NvTestnet | String value path, mapper table |
| `"Ea"` | Ea | String value path, mapper table |
| `"Nope"`, `""`, empty file, whitespace only, `{}` | None, load defaults to NvTestnet (32) | No match, no mapper hit |
| `{"aws_name":"NvTestnet"}` | NvTestnet | Key match (len 8, 0x20a458) + mapper |
| `{"aws_name":"Ea"}` | Ea | Key match + mapper |
| `{"aws_name":"Nope"}` | None, load defaults | Mapper miss |
| `{"aws_name":{"NvTestnet":null}}` | NvTestnet | Mapper `{` + expect_null confirmed |
| `{"aws_name":{"Nope":null}}` | None, load defaults | Mapper miss after null check |
| `{"aws_name":{"NvTestnet":123}}` | None, load defaults | Mapper `{` path requires string + `:` + null |
| `{"aws_name":null}`, `{"aws_name":32}` | None, load defaults | Value is not string or `{` |
| `{"other":"x","aws_name":"Ea"}` | Ea | Object loop skips other keys |
| `{"aws_name":"Ea","other":"x"}` | Ea | Object loop continues after first match |
| `{"other":"x"}` | None, load defaults | No key match |
| `{"AWS_NAME":"NvTestnet"}` | None, load defaults | Key length/content mismatch |
| `"NvTest\nnet"` (backslash present) | None | Binary decodes escapes; decoded string then misses the table |
| `{"aws_name":"NvTestnet\""}` (backslash present) | None | Same, decoded string misses the table |
| `{"aws_name":"Nv\u0054estnet"}` | None | **Candidate divergence**: binary decoder yields `NvTestnet`, which hits the table |
| `{"aws_name":{"NvTestnet":null,"x":1}}` | None | **Candidate divergence**: binary object loop continues past the extra key |
| `{"aws_name":"Ea"} garbage`, `"Ea" garbage`, `{"aws_name":"Ea"` | Ea (reference returns on match) | Trailing/closure handling not traced to a conclusion |
| `{ "aws_name" : { "NvTestnet" : null } }` | NvTestnet | Whitespace skipping confirmed in all three functions |
| `{"aws_name":{"NvTestnet"}}` | None | Mapper `{` path requires `:` + null |
| `["NvTestnet"]` | None | Main parser array path does not yield an AwsName |

## Results and limitations

Metrics with explicit denominators:

- Key comparison: 1/1 confirmed (length 8 + 8-byte compare at
  0x20a458).
- Variant discriminants present in the mapper window: 76/76
  values in the 0-75 range, as a set; the jump-table order was
  not mapped one-by-one to variant names in this packet.
- Externally-tagged null check: 4/4 bytes confirmed
  (`n`, `u`, `l`, `l`).
- Escape rejection as written in the reference: 0/1, the binary
  uses a decoder instead.
- Extra-key, duplicate-key, and trailing-byte behaviour:
  not concluded, 0/3 claimed.

What remains unknown, and why no gate is requested: the
candidate divergences above need an isolated, authorised
execution harness (per the project rule for captured binaries)
before they can be stated as output differences, and the
duplicate-key and trailing-byte branches need to be traced to
a conclusion. This packet covers only the bounded question
above, not the whole static_config component.

Next question: run the two candidate inputs
(`Nv\u0054estnet` and externally-tagged with an extra key)
through an isolated harness, or trace the mapper/main-parser
return path for duplicate keys and trailing bytes, and record
which of the three is a real output difference.
