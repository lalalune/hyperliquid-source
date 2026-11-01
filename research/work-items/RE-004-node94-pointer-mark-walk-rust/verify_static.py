"""Full-identity and downstream static controls; no captured execution."""
import json
import struct
import oracle


def check():
    original = oracle.prior.TARGET.read_bytes()
    facts = oracle.admit()
    frozen = json.loads((oracle.PACKET / "frozen/ORACLE-FREEZE.json").read_text())
    oracle.require(facts == frozen["static_facts"], "Frozen static facts changed")
    secs, offset = oracle.mapping(original)
    eh = next(s for s in secs if s["name"] == ".eh_frame")["address"]
    relocation = next(s for s in secs if s["name"] == ".rela.dyn")["address"]
    cases = {
        "mark_load": (0x50e69fb, None),
        "count_shift": (0x50e6a10, None),
        "wrapping_add": (0x50e6a11, None),
        "zero_count_gate": (0x50e6a14, None),
        "sentinel": (0x50e6a26, None),
        "fixed_inline_boundary": (0x50e6a36, None),
        "head_offset": (0x50e6a47, None),
        "next_load_before_store": (0x50e6a58, None),
        "stamp_store": (0x50e6a5b, None),
        "payload_load": (0x50e6a6a, None),
        "sentinel_branch": (0x50e6a72, None),
        "outer_equality": (0x50e6a7f, None),
        "last_return": (0x50e6a81, None),
        "padding": (0x50e6a82, None),
        "preceding_gap": (0x50e69ef, None),
        "fde_extent": (eh + 0x297df0 + 12, None),
        "leaf_cie": (eh + 17, None),
        "caller_cie": (eh + 0x6205d0 + 17, None),
        "unexpected_naming_relocation": (relocation + 16, struct.pack("<q", oracle.prior.START)),
    }
    for index, (site, _, _) in enumerate(oracle.prior.CALLERS):
        cases[f"caller_{index + 1}_edge"] = site + 1, None
    controls = {}
    for label, (address, replacement) in cases.items():
        changed = bytearray(original)
        if replacement is None:
            changed[offset(address, 1)] ^= 1
        else:
            begin = offset(address, len(replacement))
            changed[begin:begin + len(replacement)] = replacement
        try:
            oracle.structure(changed)  # Deliberately skip only whole-file SHA.
        except ValueError as error:
            controls[label] = {"va": hex(address), "rejected": str(error)}
        else:
            raise ValueError(f"Structural corruption accepted: {label}")
    return {"target_sha256": oracle.prior.SHA256, "leaf_instructions": len(facts["leaf"]),
            "caller_instructions": [len(rows) for rows in facts["callers"]],
            "structural_controls": controls, "captured_execution": False}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
