"""Derive a compact uac count witness for a fresh selected named checkpoint."""

import argparse
import hashlib
import json
from pathlib import Path
from types import ModuleType

UAC_FILE = "RE-009-node115-rmp-locus-uac-root/compare_uac.py"
MAX_RESERVED_ROWS = 0x1249
UAC_SHA = "970d1777f4327573d82ec80d28ed67cb422e72c623d480638b95595ad0ccc018"


def load_uac(folder):
    path = folder / UAC_FILE
    source = path.read_bytes()
    if hashlib.sha256(source).hexdigest() != UAC_SHA:
        raise ValueError("uac projection source pin mismatch")
    uac = ModuleType("node115_fresh_uac")
    exec(compile(source, str(path), "exec"), uac.__dict__)
    return uac


def derive(uac, activity, kit, height, checkpoint, checkpoint_pin):
    activity.word(height, "checkpoint height")
    count, _, _ = uac.read_checkpoint(activity, kit, checkpoint, checkpoint_pin, height)
    if count > MAX_RESERVED_ROWS:
        raise ValueError("uac row count exceeds the verified fresh reservation scope")
    return {"height": height, "checkpoint_sha256": checkpoint_pin, "uac_compact_count": count}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helpers", type=Path)
    parser.add_argument("height", type=int)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("checkpoint_sha256")
    args = parser.parse_args()
    try:
        uac = load_uac(args.helpers)
        activity, kit = uac.load_helpers(args.helpers)
        witness = derive(uac, activity, kit, args.height, args.checkpoint, args.checkpoint_sha256)
    except (OSError, ValueError) as error:
        parser.exit(2, f"{error}\n")
    print(json.dumps(witness, sort_keys=True))


if __name__ == "__main__":
    main()
