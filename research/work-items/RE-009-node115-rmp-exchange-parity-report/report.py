"""Report five exact-height Exchange checkpoint parity checks together."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

CHECKS = {
    "direct": ("direct-leaves/compare_leaves.py",
               "949b4a0f5789f0cb21c263de9517454ca2db6b099ba7d874c485e8d31d50e0d7",
               (23, 24, 38, 46, 50, 55), "all_direct_leaves_match"),
    "bucket_guards": ("bucket-guards/compare_guards.py",
                      "1d55ae340a309bdaf6b0fc7b99f38b7e79f8b410b0011c3c5f5dd8b114355a25",
                      (4, 5, 14, 20, 33, 43), "all_guard_subtrees_match"),
    "times": ("times/compare_times.py",
              "14c0665b0cab4b0b0e6ecbbce4bbbd202f2d7b0328920053fecd7acca71a6ceb",
              (15, 16, 45), "all_time_leaves_match"),
    "limits": ("limit-leaves/compare_limits.py",
               "079b16ec99fa1e5fedf934da0d463587fd005cbd2d7de9f4a3f93f71a8043f82",
               (12, 13, 17, 25), "all_limit_fields_match"),
    "quantities": ("quantity-subtrees/compare_quantities.py",
                   "3d7e7122d367c786234fe2721223ce1c68149112f14e3ccbb4b7b1b45fa16ee2",
                   (26, 27, 47), "all_quantity_subtrees_match"),
}


def load_checks(folder):
    checks = {}
    for label, (suffix, pin, _, _) in CHECKS.items():
        path = folder / ("RE-009-node115-rmp-exchange-" + suffix)
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != pin:
            raise ValueError(f"source pin mismatch for {path.name}")
        module = ModuleType(f"exchange_parity_{label}")
        exec(compile(source, str(path), "exec"), module.__dict__)
        checks[label] = module
    return checks


def report(folder, helper, height, checkpoint, checkpoint_pin, reference, reference_pin):
    modules = load_checks(folder)
    checks = {}
    reference_digest = None
    for label, (_, _, slots, result_key) in CHECKS.items():
        module = modules[label]
        try:
            result = module.compare(module.load_helpers(folder), helper, height, checkpoint,
                                    checkpoint_pin, reference, reference_pin)
        except ValueError as error:
            raise ValueError(f"{label}: {error}") from error
        if result["height"] != height:
            raise ValueError(f"{label}: inconsistent comparison height")
        if reference_digest is None:
            reference_digest = result["reference_raw_digest"]
        elif result["reference_raw_digest"] != reference_digest:
            raise ValueError(f"{label}: inconsistent raw ABCI reference")
        checks[label] = {"scoped_slots": list(slots), "matches": result[result_key], "detail": result}
    return {
        "height": height, "checkpoint_sha256": checkpoint_pin, "reference_sha256": reference_pin,
        "reference_raw_digest": reference_digest,
        "scope": "named-checkpoint-exchange-selected-slots",
        "scoped_slot_count": len({slot for group in checks.values() for slot in group["scoped_slots"]}),
        "all_scoped_groups_match": all(group["matches"] for group in checks.values()),
        "groups": checks,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helpers", type=Path)
    parser.add_argument("driver", type=Path)
    parser.add_argument("height", type=int)
    parser.add_argument("checkpoint", type=Path)
    parser.add_argument("checkpoint_sha256")
    parser.add_argument("reference", type=Path)
    parser.add_argument("reference_sha256")
    args = parser.parse_args()
    try:
        result = report(args.helpers, args.driver, args.height, args.checkpoint,
                        args.checkpoint_sha256, args.reference, args.reference_sha256)
    except (ValueError, OSError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["all_scoped_groups_match"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
