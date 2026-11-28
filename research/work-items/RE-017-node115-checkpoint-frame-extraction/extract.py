"""Decode a pinned local #115 checkpoint archive member to an RMP file."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import tempfile

import lz4.frame

FRAME_MAGIC = b"\x04\x22\x4d\x18"
CHUNK_SIZE = 1 << 20


def sha256_text(value):
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("expected a lowercase SHA-256 digest")
    return value


def extract(source, destination, archive_sha256, checkpoint_sha256, limit):
    sha256_text(archive_sha256)
    sha256_text(checkpoint_sha256)
    if limit < 1:
        raise ValueError("maximum output size must be positive")
    if destination.exists():
        raise FileExistsError(destination)
    with source.open("rb") as raw:
        if hashlib.file_digest(raw, "sha256").hexdigest() != archive_sha256:
            raise ValueError("compressed archive SHA-256 mismatch")
        raw.seek(0)
        if raw.read(len(FRAME_MAGIC)) != FRAME_MAGIC:
            raise ValueError("expected an LZ4 frame")
        raw.seek(0)

        with tempfile.TemporaryDirectory(dir=destination.parent) as directory:
            pending = Path(directory) / "checkpoint.rmp"
            digest = hashlib.sha256()
            written = 0
            with lz4.frame.open(raw, "rb") as decoded, pending.open("wb") as output:
                while chunk := decoded.read(min(CHUNK_SIZE, limit - written + 1)):
                    written += len(chunk)
                    if written > limit:
                        raise ValueError("decoded checkpoint exceeds maximum output size")
                    digest.update(chunk)
                    output.write(chunk)
            if digest.hexdigest() != checkpoint_sha256:
                raise ValueError("decoded checkpoint SHA-256 mismatch")
            os.link(pending, destination)
    return written


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--checkpoint-sha256", required=True)
    parser.add_argument("--max-output-bytes", type=int, required=True)
    args = parser.parse_args()
    try:
        count = extract(
            args.source, args.destination, args.archive_sha256,
            args.checkpoint_sha256, args.max_output_bytes,
        )
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(f"verified archive and checkpoint digests; wrote {count} bytes")


if __name__ == "__main__":
    main()
