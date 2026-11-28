# RE-017: Extract a pinned node #115 checkpoint archive frame

The [startup checkpoint worker](../RE-017-node115-checkpoint-compression/README.md)
passes the checkpoint path to the external LZ4 compressor. This packet
provides a local extraction step for a supplied standard LZ4 frame.
It checks the compressed object SHA-256 before decoding and verifies the
separately supplied SHA-256 of the resulting checkpoint. A failed check
leaves the destination unpublished. Reading proceeds in chunks with an
explicit output bound and leaves the source file in place.

The verifier checks the Linux x86-64 #115 artifact digest, owning FDE and
compression command format bytes. The observed worker uses the standard
CLI path. The synthetic tests use the public LZ4 frame library to generate
local inputs. They exercise chunked extraction and reject incorrect
digests, a non-frame prefix, an output limit violation and replacement
of an existing file.

This step establishes identity against supplied digests. It does not
provide the archive bytes or their producer provenance, parse the
resulting RMP state, determine its block height, or compute a state
root. No download, captured code execution or transfer is performed.

For Python 3.11 or later with the optional `lz4==4.4.5` package:

```sh
packet=research/work-items/RE-017-node115-checkpoint-frame-extraction
python3 -B "$packet/verify.py"
python3 -B -m unittest discover -v -s "$packet" -p test_extract.py
python3 -B "$packet/extract.py" checkpoint.rmp.lz4 checkpoint.rmp \
  --archive-sha256 "$archive_sha" --checkpoint-sha256 "$checkpoint_sha" \
  --max-output-bytes "$max_output_bytes"
```

[Raw offline output](offline-log.txt)
