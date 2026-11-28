# RE-011 #115 offline LtHash checkpoint sidecar projection

The EVM materializer can load optional hash state when it restores a checkpoint. The [checkpoint hash evidence](../RE-011-evm-db-checkpoint-hashes-115/README.md) identifies the native path, JSON schema, cache-to-rebuild branch and state layout. A supplied `checkpoint/H/lt_hashes.json` can now be checked offline against its recorded file digest and projected into the three records used by that cache path.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The [native checkpoint lifecycle](../RE-009-node115-checkpoint-lifecycle/README.md) traces the copy from the selected checkpoint directory. The loader at `0x38c2690` calls `0x422e730` at `0x38c2749`, tests the result, and supplies absent options to the three constructors on the selected read error. The writer projection at `0x38c2230` and `0x36c5cf0` supplies the schema implemented here.

| Name | Offset in the ordered cache records |
| --- | ---: |
| `accounts_hash` | `0x0000` |
| `contracts_hash` | `0x0810` |
| `storage_hash` | `0x1020` |

Each record has the 2,048 hash bytes in original byte order, then two unsigned 64-bit little-endian words `n_elements` and `n_bytes` at offsets `0x800` and `0x808`. The file representation uses named objects, integer counters and arrays of integer bytes. The parser checks that writer-emitted shape and orders the three records independently of input JSON key order. The CLI prints each projected record's length, counters and SHA-256. Programmatic users can obtain the bytes with `project(raw, expected_sha256)`.

## Reproduce offline

```sh
python3 -B -m unittest tests.test_re011_evm_checkpoint115
python3 -B research/work-items/RE-011-node115-lthash-sidecar-projection/test_sidecar.py
python3 -B research/work-items/RE-011-node115-lthash-sidecar-projection/read_sidecar.py \
  /path/to/checkpoint/H/lt_hashes.json --sha256 EXPECTED_FILE_SHA256
```

The test suite writes a synthetic sidecar to an isolated temporary directory, checks all three marker offsets and verifies that the CLI distinguishes an unavailable file from a valid projected result. Additional controls check file identity, UTF-8, duplicate keys, unsigned ranges and byte lengths. The [offline log](offline-log.txt) includes the pinned static evidence suite and the fresh projection tests.

The reader is limited to the native writer's named-object and byte-array shape. The upstream diagnostic records additional decoder forms and rebuild behavior, which are outside this projection. The sidecar's provenance and height must come from the surrounding capture, and the projected record SHA-256 values identify only the local cache bytes. ABCI root comparison still requires separately typed ABCI reference roots. This work reads only local files.
