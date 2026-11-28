# RE-009 Node #115 positional JSON checkpoint root cadence

The JSON checkpoint restore reader accepts a positional array for the nested `ExchangeMisc` record. This packet resolves the cadence field on that array arm. The field shares the unsigned scalar parser and historical output slot with the [JSON object arm](../RE-009-node115-json-root-cadence/README.md), while its field-presence check is a separate array parser. This provides an explicit checkpoint compatibility contract for restoring the replay root divisor.

- Component: `storage` / `abci`.
- Input: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base revision: `cfeaee133b33ce9450a7434af19515b82171a8c6`.
- Coordinates and method: ELF virtual addresses, decoded with LLVM objdump 23.1.4 using Intel syntax. The verifier checks the original instruction bytes and FDE ranges directly against the pinned ELF.

## Observations

1. The nested reader `0x400cec0` dispatches byte `0x5b` (opening bracket) to `0x400db7d`, advances the cursor past it and initializes the sequence state at stack `+0x78`. The earlier keyed parent call at `0x3efd286` selects this same nested reader.
2. After the earlier fields, `0x400fb79` passes that sequence state to `0x3ef15e0`. The wrapper calls `0x3f4cb30`, whose close-bracket (`0x5d`) arm returns a successful absent-item tag without calling the scalar parser. The wrapper returns a zero word on that result. The present-item arm calls `0x3fd23d0`, the same scalar reader used by the named `aci` arm. A wrapper status of 1 bypasses cadence selection.
3. On success, `0x400fbb1..0x400fbb9` tests the full returned word in RDX. Zero, whether absent at the closing bracket or explicit, selects 1,000. A nonzero word survives unchanged. The selected word is stored at stack `+0x3e8` and forwarded to the common close-array check at `0x400dc70`.
4. The normal return copies from stack `+0x338` to temporary stack `+0x460`, then to result `+0x10`. The cadence word lands at `+0xc0`. The existing parent/materializer witness carries that same slot to decoded state `+0x1ea8` and the live root cadence divisor at `+0x39c8`.

The `aci` name is inferred from the keyed route with the same decoder and result coordinate. The default concerns the final field when earlier fields have already decoded. It does not imply arbitrary short arrays are accepted. No captured code executes, and this does not establish a real checkpoint's decoded values or a matched replay root.

## Reproduce

From the repository root:

```sh
python3 -B research/work-items/RE-009-node115-positional-json-root-cadence/verify.py
```

[Offline output](offline-log.txt) | [Instruction windows](windows.txt)
