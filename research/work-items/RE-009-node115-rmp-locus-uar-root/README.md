# RE-009 #115 complete named Locus uaR raw subtree comparison

Check `exchange.locus.uaR` at native raw path `[0,7]` against an independently pinned raw ABCI tree. The comparer reproduces the entire supplied raw digest and independently checks the internal Context height leaf before comparing this subtree.

The field writer joins Locus `+0x9f8` to `0x5678ae0` and the named collection writer `0x52bab90`. Selected rows hold Address and an ordered sequence of enum values. The serialized variants `Perp`, `Spot`, `Token` and `Pdi` are single-key maps with unsigned word payloads and tags 0–3. `ActivateDexAbstraction`, `ActivateUnifiedAccount` and `AllBoleTokens` are strings with tags 4–6 and no payload. The named and raw jump tables select the same ordinal space. [#6591](https://github.com/lalalune/hyperliquid-source/pull/6591) and [#6592](https://github.com/lalalune/hyperliquid-source/pull/6592) provide the earlier reader evidence.

| Relative path | Preimage or structure |
|---|---|
| `[0]` | Ordered 20-byte Address keys |
| `[1,0,0..3]` | One ordered little-endian qword stream per numeric variant that occurs |
| `[1,0,4]` | One shared little-endian qword stream of every tag |
| `[1,1]` | Little-endian count per user, including zero |
| `[2]` | Total user count as a little-endian qword |

Raw visitor `0x3c52840` builds the top-level address, value and user-count slices before `0x41adc70`. All user values visit the same subtree. Value visitor `0x4510ac0` feeds every ordered enum record to the same branch and appends a per-user count separately. The enum writer `0x3b82f10` checks a five-child branch initialized by `0x3b82eb0`. Tags 0–3 send their payload to the tag-ordinal child and write their shared tag into child 4. Tags 4–6 write only child 4. If all users have zero enum records the enum branch is absent. An empty user map only emits total count. The packet reconstructs the stored representation and makes no claims about action semantics.

Use exact source pins and helper directory layout from [#7445](https://github.com/lalalune/hyperliquid-source/pull/7445), [#7404](https://github.com/lalalune/hyperliquid-source/pull/7404) and [#7344](https://github.com/lalalune/hyperliquid-source/pull/7344). From the checkout root, run `python -B research/work-items/RE-009-node115-rmp-locus-uar-root/verify.py --helpers PATH --rustc PATH`. The verifier reads authenticated ELF bytes and uses synthetic populated, unit-only and empty controls. It changes shared tag order and counts independently. No genuine checkpoint or measured network root is included.
