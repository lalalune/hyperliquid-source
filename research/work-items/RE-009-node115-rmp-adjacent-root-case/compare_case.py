"""Check the restored Context and first replay begin fields against adjacent raw exports."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from types import ModuleType

DEPENDENCIES = {
    "messagepack": ("RE-009-node115-msgpack-context-projection/project.py",
                    "77b38608aca44aac753c6440038b5baf2646474846aaba911794ed99f84be3cf"),
    "normalizer": ("RE-009-node115-checkpoint-context-projection/project.py",
                   "5b8f909500007bc23aa6ce46d0d9abf79fab081e6a35a68587d07edec95bbebd"),
    "context": ("RE-009-node115-context-subtree-compare/compare.py",
                "9fe1de5c63e742c1974b8ecb2888e7acaca80d95a599d54178bc7f38edf15241"),
    "begin": ("RE-009-node115-adjacent-context-begin-roots/transition.py",
              "7c734e22c20a86a6b0371f24dd7c061d8cfe3b9b2631e52d31afe23fbf1a94aa"),
    "tree": ("RE-009-node115-context-root-isolation/isolate.py",
             "acb3c71a3c56b42d9614aeb78225cfc90f364e8468db144c0f55e22a175fc3ec"),
}
ROLES = {"checkpoint_rmp", "successor_header", "reference_h", "reference_h_plus_one"}


def load_dependencies(folder):
    modules = {}
    for name, (relative, sha256) in DEPENDENCIES.items():
        path = folder / relative
        source = path.read_bytes()
        if hashlib.sha256(source).hexdigest() != sha256:
            raise ValueError(f"published helper pin mismatch for {relative}")
        module = ModuleType(f"node115_{name}")
        module.__file__ = str(path)
        exec(compile(source, str(path), "exec"), module.__dict__)
        modules[name] = module
    return modules


def artifact(manifest, entry):
    if type(entry) is not dict or set(entry) != {"path", "sha256"}:
        raise ValueError("expected artifact path and SHA-256")
    return manifest.parent / entry["path"], entry["sha256"]


def hash_bytes(helper, tree, preimage):
    result = subprocess.run([helper.resolve()], input=preimage, check=True, capture_output=True)
    text = result.stdout.decode("ascii").strip()
    if not tree.DIGEST.fullmatch(text):
        raise ValueError("BLAKE3 helper returned an invalid leaf digest")
    return text


def restored_reference(toolkit, helper, reference, height, restored):
    tree, context = toolkit["tree"], toolkit["context"]
    declared, parsed = tree.read_export(*reference, height)
    if tree.digest(helper, parsed) != declared:
        raise ValueError(f"height {height} reference tree disagrees with its recorded raw digest")
    expected_input = context.preimages(restored)
    digest_sequence = (hash_bytes(helper, tree, leaf) for leaf in context.leaves(expected_input))
    expected = tree.decode_tree(context.replace_leaves(expected_input, digest_sequence))
    actual = tree.at_path(parsed, (0, 0))
    actual_fields = dict(actual)
    return {
        "height": height,
        "reference_raw_digest": declared,
        "all_context_fields_match": expected == actual,
        "different_context_fields": [context.KEYS[index] for index, value in expected
                                     if value != actual_fields.get(index)],
        "ordered_context_slots": [index for index, _ in expected] == [index for index, _ in actual],
    }


def compare_case(manifest, sha256, toolkit, helper):
    begin = toolkit["begin"]
    case = begin.pinned_json(manifest, sha256)
    if set(case) != {"height", *ROLES}:
        raise ValueError("expected case height and all four input roles")
    height = begin.u64(case["height"], "requested checkpoint height")
    inputs = {role: artifact(manifest, case[role]) for role in ROLES}
    decoded = toolkit["messagepack"].project_rmp(
        *inputs["checkpoint_rmp"], height, toolkit["normalizer"],
    )
    header = begin.pinned_json(*inputs["successor_header"])
    _, after, rotated = begin.transition(decoded, header)
    h = restored_reference(toolkit, helper, inputs["reference_h"], height, decoded)
    h_plus_one = begin.compare_export(toolkit["tree"], helper, inputs["reference_h_plus_one"], after)
    return {
        "clock_rotated": rotated, "checkpoint_context": h, "successor_begin": h_plus_one,
        "selected_checks_pass": h["all_context_fields_match"] and all(h_plus_one["matched"].values()),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("helper_folder", type=Path)
    parser.add_argument("blake3_helper", type=Path)
    parser.add_argument("case_manifest", type=Path)
    parser.add_argument("case_manifest_sha256")
    args = parser.parse_args()
    try:
        result = compare_case(args.case_manifest, args.case_manifest_sha256,
                              load_dependencies(args.helper_folder), args.blake3_helper)
    except (ValueError, OSError, KeyError, TypeError, RecursionError, subprocess.SubprocessError) as error:
        parser.error(str(error))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["selected_checks_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
