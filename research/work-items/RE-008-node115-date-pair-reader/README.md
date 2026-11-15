# RE-008: Date sequence element's selected pair path

Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. This static packet follows the `0x31f91f0` element reader called by the sequence visitor in open #6613. No captured code is executed.

## Selected fixarray observations

- In the selected fresh-marker path, byte ranges `0x80..0x8f` and `0x90..0x9f` branch separately; the latter masks the low nibble and enters `0x31f9361`. This packet covers only that latter arm, not all marker table routes.
- The selected arm reads a 16-bit decoder field at `+0x22`, checks for zero, decrements and stores it, and branches away if the result is zero. The field's meaning and complete error handlers are not established.
- With nonzero low-nibble count, the arm calls `0x2f68710` with the four target bytes `Date`, and checks for result tag `9`. With count at least two it then calls `0x3242730` with a zero third argument and checks tag `9`. Open #6598 maps that latter reader's `a` and `c` fields; this packet treats both helper bodies as boundaries.
- Counts zero and one reach separate calls to `0x2f7fe90` with `esi` equal to zero and one, respectively. For counts at least two, after both selected helpers succeed, the body saves `count - 2`; a nonzero remainder constructs a record with byte `4` before a shared return path. The target's error semantics are not inferred from this byte alone.
- An unwind record covers `0x31f91f0..0x31f9b70`, and the complete interval is retained as a review aid. The pair's key/value roles are inferred from #6598/#6613 context; this packet does not prove the meaning of the fields, all input variants, dynamic reachability or full equivalence with the map representation. No component gate is advanced.

## Reproduce

```sh
python3 research/work-items/RE-008-node115-date-pair-reader/verify.py
readelf -wf artifacts/node/115/hl-node | rg 'pc=00000000031f91f0'
/usr/bin/objdump -d --x86-asm-syntax=intel --start-address=0x31f91f0 --stop-address=0x31f9b70 artifacts/node/115/hl-node
```

The verifier authenticates the target SHA-256, checks ten selected instruction/string anchors and four direct-call targets, and rejects ten single-byte anchor mutations. FDE inspection is independent of the verifier. These checks do not establish full CFG coverage, helper contracts, all error cases or input authenticity. Open #6598 excludes the sequence element path; #6613 records its caller but explicitly excludes this helper's body.
