# RE-017 #115 local MessagePack Context hardfork projection

The local startup MessagePack decoder reaches a distinct Context visitor, `0x1b3e730`. On its selected successful map return, `hardfork.version` is the unsigned word at output +0x18 and `hardfork.round` is the unsigned word at +0x20. The enclosing reader stages both words together before resuming the field loop.

| Boundary | Static evidence |
| --- | --- |
| Local reader | The [local-state restore packet](../RE-017-local-state-restore-115/README.md) identifies the binary branch into `0x1b44f30`. The selected `exchange` call at `0x1b45512` reaches `0x199ce60`. The direct child edges at `0x199cfcc`, `0x1850c6c`, and `0x1ac8d3f` continue through `0x1850600` and `0x1ac8460` into the Context visitor. |
| Context field | The local string selector `0x27401e0` classifies `hardfork` as 1. Table `0x5768c8` maps that index to `0x1b3ef6e`. With the field unseen, the call at `0x1b3ef87` reaches the local hardfork child `0x1a32fa0`. |
| Child result | The overlapping key comparisons decode `version` and `round` to the two arms that use unsigned reader slot `0x64e2580`. With both fields present, the child returns tag 9, version at +8 and round at +16. |
| Map return | The tag-9 arm stages the two payload words at stack+0xf0 and stack+0xe8. On the selected completion with height present, the Context writes those words into +0x18/+0x20 and substitutes zero for each when the entire hardfork field is absent. |
| Caller stage | The caller's Context output begins at stack+0xc70. `0x1ac8d95` reads 16 bytes at stack+0xc88. On the non-2 result path, `0x1ac8d99`, `0x1ac8e20` and `0x1ac8e28` carry both words through stack+0x610 to stack+0x1810. |

The result identifies the serialized pair for fixtures targeting the local reader and pins where its caller takes ownership. The [checkpoint visitor](https://github.com/lalalune/hyperliquid-source/pull/7253) gives the same layout via different linked addresses. This packet ends at the caller's staging slot. Later aggregate copies and the effect of the optional startup hardfork on the eventual replay comparison still need to be checked.

## Offline verification

Run from the repository root:

```sh
python3 -B research/work-items/RE-017-node115-local-context-hardfork/verify.py
```

The verifier reads the authenticated ELF as data. The [raw output](offline-log.txt) records the digest, selected call and selector targets, pair offsets and caller projection. The [witness instructions](windows.txt) are also checked against the pinned capture.
