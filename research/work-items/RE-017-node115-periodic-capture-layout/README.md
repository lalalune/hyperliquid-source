# RE-017 #115 periodic capture payload, status, and rolling link

The [periodic pathname analysis](../RE-008-periodic-state-path-115/README.md) identifies two native paths at each selected height. The earlier [linked state packet](../RE-008-linked-abci-state-115/README.md) inferred the status pathname was used for the hard link. Reading both returned string positions through the selected caller shows that the periodic payload, status marker, and rolling snapshot are three separate paths. A local capture inspector now identifies them and verifies the archived payload digest before reporting marker and rolling-file observations.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

| Local path relative to the node root | Selected native role |
| --- | --- |
| `data/periodic_abci_states/YYYYMMDD/H.rmp` | First pathname returned by `0x38d8240`, built through `0x38d8100`. The caller stages it at stack `+0x20` and sends it in the serialized state capture. The later link helper receives the same pathname as its first pair. |
| `data/periodic_abci_state_statuses/YYYYMMDD/H` | Second pathname, returned at output `+0x18`. The caller sends it to `0x1505a50` at `0x54860a0`. A regular file satisfies its initial check. On the selected creation path the writer at `0x1505b37` receives zero data length. An existing regular file therefore need not have newly written or empty contents. |
| `hyperliquid_data/abci_state.rmp` | The separate rolling pathname from `0x5942870`. The utility receives it as the second pair. The selected fallback passes the periodic pathname and a generated temporary pathname into the resolved `linkat` route, then passes that temporary pathname and the rolling pathname to the final rename helper. |

The link operation occurs after the status helper. Subsequent snapshots can make the rolling file point elsewhere while leaving the historical payload and marker intact. A copied archive can also have different file identities. The inspector reports current filesystem identity without inferring how an exported file was produced or treating a distinct rolling file as a missing historical snapshot.

## Reproduce offline

```sh
python3 -B research/work-items/RE-017-node115-periodic-capture-layout/verify.py
python3 -B research/work-items/RE-017-node115-periodic-capture-layout/test_archive.py
python3 -B research/work-items/RE-017-node115-periodic-capture-layout/inspect_archive.py \
    /path/to/local/node-root YYYYMMDD H --sha256 EXPECTED_PERIODIC_RMP_SHA256
```

The verifier authenticates the target ELF, native pathname templates, instructions, function extents and relative/dynamic call bindings. The filesystem tests create isolated payloads with a separate empty status file, absent and nonregular paths, and an actual payload-to-rolling hard link followed by replacement of the rolling path. Independent controls verify explicit coordinates and the pinned payload SHA-256. See the [instruction windows](instructions.tsv) and [offline log](offline-log.txt).

The audit reads local files only. The status marker supplies no digest. The pinned file hash authenticates only the supplied bytes against a separately obtained value. This does not establish the source node's build, an embedded height or H/H+1 state-root parity.
