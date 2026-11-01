"""Identity and downstream static corruption controls, without execution."""
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
        "initial_key_width": (0x1b26115, None),
        "initial_unsigned_branch": (0x1b26118, None),
        "node_gate_offset": (0x1b2613e, None),
        "step_increment": (0x1b2613a, None),
        "word_comparison": (0x1b26145, None),
        "loop_branch": (0x1b2614c, None),
        "exhausted_second_word": (0x1b2615d, None),
        "last_return": (0x1b26169, None),
        "padding": (0x1b2616a, None),
        "preceding_gap": (0x1b260ff, None),
        "fde_extent": (eh + 0x2e56c + 12, None),
        "leaf_cie": (eh + 17, None),
        "caller_cie": (eh + 0x2dc714 + 17, None),
        "caller_edge": (0x257699a, None),
        "unexpected_naming_relocation": (relocation + 16, struct.pack("<q", oracle.prior.START)),
    }
    controls = {}
    for label, (address, replacement) in cases.items():
        changed = bytearray(original)
        if replacement is None:
            changed[offset(address, 1)] ^= 1
        else:
            begin = offset(address, len(replacement))
            changed[begin:begin + len(replacement)] = replacement
        try:
            oracle.structure(changed)  # Deliberately skip only full-file SHA.
        except ValueError as error:
            controls[label] = {"va": hex(address), "rejected": str(error)}
        else:
            raise ValueError(f"Structural corruption accepted: {label}")
    return {"target_sha256": oracle.prior.SHA256, "leaf_instructions": len(facts["leaf"]),
            "caller_instructions": len(facts["caller"]), "structural_controls": controls,
            "captured_execution": False}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
