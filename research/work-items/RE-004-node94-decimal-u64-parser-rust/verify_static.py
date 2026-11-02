"""Identity and downstream static corruption controls; no target execution."""
import json
import struct
import oracle


def check():
    original = oracle.TARGET.read_bytes()
    facts = oracle.admit()
    frozen = json.loads((oracle.PACKET / "frozen/ORACLE-FREEZE.json").read_text())
    oracle.require(facts == frozen["static_facts"], "Frozen static facts changed")
    secs, offset = oracle.mapping(original)
    rel = next(s for s in secs if s["name"] == ".rela.dyn")["address"]
    leaf = facts["bodies"][0]
    cases = {
        "empty_gate": (0x54307ce, None), "count_width": (0x54307f0, None),
        "limit_immediate": (0x54307de, None), "limit_branch": (0x54307fa, None),
        "last_digit_bound": (0x5430803, None), "state_pointer_store": (0x5430817, None),
        "state_length_store": (0x543081d, None), "signed_byte_load": (0x5430826, None),
        "low_byte_digit_gate": (0x543082d, None), "signed_count_test": (0x5430833, None),
        "setg_only_al": (0x5430836, None), "output_store": (0x5430839, None),
        "overflow_zero_return": (0x5430840, None), "eof_success": (0x543084b, None),
        "empty_output_path": (0x5430855, None), "padding": (0x5430857, None),
        "fde_extent": (leaf["frames"]["fde"]["va"] + 12, None),
        "cie": (leaf["frames"]["cie"]["va"] + 17, None),
        "unexpected_naming_relocation": (rel + 16, struct.pack("<q", oracle.START)),
    }
    for site in oracle.SITES:
        cases[f"caller_{site:x}"] = site + 1, None
    controls = {}
    for label, (address, replacement) in cases.items():
        changed = bytearray(original)
        if replacement is None:
            changed[offset(address, 1)] ^= 1
        else:
            begin = offset(address, len(replacement))
            changed[begin:begin + len(replacement)] = replacement
        try:
            oracle.structure(changed)
        except ValueError as error:
            controls[label] = {"va": hex(address), "rejected": str(error)}
        else:
            raise ValueError(f"Structural corruption accepted: {label}")
    return {"target_sha256": oracle.TARGET_SHA,
            "body_instruction_counts": [len(x["instructions"]) for x in facts["bodies"]],
            "structural_controls": controls, "captured_execution": False}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
