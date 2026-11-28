"""Compare Cargo's six release optimization levels for one authenticated node115 function."""
import argparse
import json
from pathlib import Path
import tempfile

import build
import verify


def compare_profiles(cache, binutils_dir, node_path):
    pinned_node = node_path.read_bytes()
    packet = Path(__file__).resolve().parent
    target, offset, _ = verify.check_window(pinned_node, (packet / "umodti3.bin").read_bytes(),
                                           (packet / "control-1.94.1.bin").read_bytes())
    tools = build.binutils(binutils_dir)
    release = "1.95.0"
    rows = []
    with tempfile.TemporaryDirectory(prefix="umod-profile-matrix-") as temporary:
        root = Path(temporary).resolve()
        library = build.sources(cache, root, release, False)
        for level in ("0", "1", "2", "3", "s", "z"):
            # Discard each fresh build tree once its measured data is recorded.
            with tempfile.TemporaryDirectory(dir=root) as scratch:
                work = Path(scratch)
                archive, _, _ = build.cargo_job(work, cache, library, release, False, opt_level=level)
                record, body = build.symbol_bytes(archive, tools, work, require_no_relocations=False)
                rows.append(dict(opt_level=level, bytes=len(body), relocations=record["relocations_in_section"],
                                 sha256=record["function_sha256"],
                                 whole_raw_match=(body == target and record["relocations_in_section"] == 0)))
    return dict(node_sha256=verify.NODE_SHA, target=build.TARGET, symbol=build.SYMBOL,
                virtual_start=hex(verify.START), virtual_end=hex(verify.END), file_offset=hex(offset),
                rustc_commit=build.RELEASES[release][0], source_archive_sha256=build.RELEASES[release][1],
                profiles=rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", required=True, type=Path, help="source and Cargo cache provisioned by build.py")
    parser.add_argument("--binutils-dir", type=Path)
    parser.add_argument("--node", type=Path, default=verify.ROOT / "artifacts/node/115/hl-node")
    args = parser.parse_args()
    print(json.dumps(compare_profiles(args.cache.resolve(), args.binutils_dir, args.node), indent=2))


if __name__ == "__main__":
    main()
