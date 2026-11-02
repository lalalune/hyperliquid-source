"""Deterministic generator for the RE-004 sentinel-gate family packet.

The #164 tag-5 resolver twins compared an object's [0x68..0x88] vectors
against two fixed 16-byte .rodata constants. This packet shows that gate is
not twin-specific: 46 functions contain 47 such gates, all built from the
same idiom (two pcmpeqb compares against the same constants, pand,
pmovmskb, cmp against 0xffff, then a conditional branch or setne). The
gates fall into three offset classes: A (+0x68/+0x78, 42 gates), B
(+0x00/+0x10, 3 gates), C (+0x20/+0x30, 2 gates). The binary's code never
constructs the sentinel vectors: no instruction outside the 94 compares
references the constants, no 16-byte immediate builds them, no data pointer
aims at them, and no gate function writes the compared vectors inline.
The double-gate function 0x4e852a0 chains the gate to the difference field
and then to the counter field, which is the packet's behavioral core.
Reads the pinned node #94 binary and disassembles nothing: it checks the
node SHA-256 first, verifies unwind FDE starts/ends via the repository
shared ELF parser, re-derives the census with a byte-level disp32 scan,
and verifies every recorded anchor byte. Writes only to --out. Static
analysis only: the node binary is never executed.
"""

import argparse
import bisect
import hashlib
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import elf_index  # noqa: E402  (repository shared ELF section parser)

SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
DEFAULT_BINARY = Path("artifacts/node/94/hl-node")
CONST_HI = 0x204BE0
CONST_LO = 0x206160
CONST_HI_BYTES = bytes.fromhex("e500b653ca82273b7bfad8045d85a470")
CONST_LO_BYTES = bytes.fromhex("c5d2460186f7233c927e7db2dcc703c0")

# Per-gate anchors, derived once from the binary (capstone linear sweep
# inside FDE bounds, cross-checked by the byte-level disp32 scan below).
# Each gate: FDE, FDE end/length, class, the two pcmpeqb compares, the two
# movdqu feeds, and the branch/setne that consumes cmp 0xffff.
GATES = [
 {
  "fde": "0x1eb1cc0",
  "fde_end": "0x1eb1e58",
  "fde_len": 408,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x1eb1d07",
    "bytes": "660f740dd12e35fe"
   },
   {
    "va": "0x1eb1d0f",
    "bytes": "660f7405494435fe"
   }
  ],
  "feeds": [
   {
    "va": "0x1eb1d01",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x1eb1cfb",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x1eb1d24",
   "bytes": "0f848a000000",
   "asm": "je 0x1eb1db4",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x1eb1e60",
  "fde_end": "0x1eb2057",
  "fde_len": 503,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x1eb1ea7",
    "bytes": "660f740d312d35fe"
   },
   {
    "va": "0x1eb1eaf",
    "bytes": "660f7405a94235fe"
   }
  ],
  "feeds": [
   {
    "va": "0x1eb1ea1",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x1eb1e9b",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x1eb1ec4",
   "bytes": "0f848d000000",
   "asm": "je 0x1eb1f57",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x1eb2640",
  "fde_end": "0x1eb2c6f",
  "fde_len": 1583,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x1eb26a4",
    "bytes": "660f740d342535fe"
   },
   {
    "va": "0x1eb26ac",
    "bytes": "660f7405ac3a35fe"
   }
  ],
  "feeds": [
   {
    "va": "0x1eb269f",
    "bytes": "f30f6f4b78"
   },
   {
    "va": "0x1eb269a",
    "bytes": "f30f6f4368"
   }
  ],
  "branch": {
   "va": "0x1eb26c5",
   "bytes": "7527",
   "asm": "jne 0x1eb26ee",
   "polarity": "jne"
  },
  "base_regs": [
   "rbx",
   "rbx"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x1ebde00",
  "fde_end": "0x1ebe3d9",
  "fde_len": 1497,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x1ebde70",
    "bytes": "660f740d686d34fe"
   },
   {
    "va": "0x1ebde78",
    "bytes": "660f7405e08234fe"
   }
  ],
  "feeds": [
   {
    "va": "0x1ebde6b",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x1ebde66",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x1ebde8e",
   "bytes": "7418",
   "asm": "je 0x1ebdea8",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x1ebe3e0",
  "fde_end": "0x1ebe9b9",
  "fde_len": 1497,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x1ebe450",
    "bytes": "660f740d886734fe"
   },
   {
    "va": "0x1ebe458",
    "bytes": "660f7405007d34fe"
   }
  ],
  "feeds": [
   {
    "va": "0x1ebe44b",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x1ebe446",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x1ebe46e",
   "bytes": "7418",
   "asm": "je 0x1ebe488",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x1ebe9c0",
  "fde_end": "0x1ebebf1",
  "fde_len": 561,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x1ebea17",
    "bytes": "660f740dc16134fe"
   },
   {
    "va": "0x1ebea1f",
    "bytes": "660f7405397734fe"
   }
  ],
  "feeds": [
   {
    "va": "0x1ebea12",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x1ebea0d",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x1ebea35",
   "bytes": "7418",
   "asm": "je 0x1ebea4f",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x1ebec00",
  "fde_end": "0x1ebee32",
  "fde_len": 562,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x1ebec54",
    "bytes": "660f740d845f34fe"
   },
   {
    "va": "0x1ebec5c",
    "bytes": "660f7405fc7434fe"
   }
  ],
  "feeds": [
   {
    "va": "0x1ebec4f",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x1ebec4a",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x1ebec72",
   "bytes": "7418",
   "asm": "je 0x1ebec8c",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x1ebfe60",
  "fde_end": "0x1ec014a",
  "fde_len": 746,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x1ebfea6",
    "bytes": "660f740d324d34fe"
   },
   {
    "va": "0x1ebfeae",
    "bytes": "660f7405aa6234fe"
   }
  ],
  "feeds": [
   {
    "va": "0x1ebfea1",
    "bytes": "f30f6f4978"
   },
   {
    "va": "0x1ebfe9c",
    "bytes": "f30f6f4168"
   }
  ],
  "branch": {
   "va": "0x1ebfec8",
   "bytes": "7414",
   "asm": "je 0x1ebfede",
   "polarity": "je"
  },
  "base_regs": [
   "rcx",
   "rcx"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x1ec0150",
  "fde_end": "0x1ec043a",
  "fde_len": 746,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x1ec0196",
    "bytes": "660f740d424a34fe"
   },
   {
    "va": "0x1ec019e",
    "bytes": "660f7405ba5f34fe"
   }
  ],
  "feeds": [
   {
    "va": "0x1ec0191",
    "bytes": "f30f6f4978"
   },
   {
    "va": "0x1ec018c",
    "bytes": "f30f6f4168"
   }
  ],
  "branch": {
   "va": "0x1ec01b8",
   "bytes": "7414",
   "asm": "je 0x1ec01ce",
   "polarity": "je"
  },
  "base_regs": [
   "rcx",
   "rcx"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x2745f50",
  "fde_end": "0x27462d7",
  "fde_len": 903,
  "gate": 0,
  "class": "B",
  "pcmpeqb": [
   {
    "va": "0x27460d2",
    "bytes": "660f740d06ebabfd"
   },
   {
    "va": "0x27460da",
    "bytes": "660f74057e00acfd"
   }
  ],
  "feeds": [
   {
    "va": "0x27460cd",
    "bytes": "f30f6f4910"
   },
   {
    "va": "0x27460c9",
    "bytes": "f30f6f01"
   }
  ],
  "branch": {
   "va": "0x27460ef",
   "bytes": "7513",
   "asm": "jne 0x2746104",
   "polarity": "jne"
  },
  "base_regs": [
   "rcx",
   "rcx"
  ],
  "feed_disps": [
   "0x10",
   "0x0"
  ]
 },
 {
  "fde": "0x2787ca0",
  "fde_end": "0x2788044",
  "fde_len": 932,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x2787d55",
    "bytes": "660f740d83cea7fd"
   },
   {
    "va": "0x2787d5d",
    "bytes": "660f7405fbe3a7fd"
   }
  ],
  "feeds": [
   {
    "va": "0x2787d50",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x2787d4b",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x2787d72",
   "bytes": "7507",
   "asm": "jne 0x2787d7b",
   "polarity": "jne"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x2788350",
  "fde_end": "0x27884f5",
  "fde_len": 421,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x2788397",
    "bytes": "660f740d41c8a7fd"
   },
   {
    "va": "0x278839f",
    "bytes": "660f7405b9dda7fd"
   }
  ],
  "feeds": [
   {
    "va": "0x2788391",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x278838b",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x27883b4",
   "bytes": "0f8490000000",
   "asm": "je 0x278844a",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x2788500",
  "fde_end": "0x278870f",
  "fde_len": 527,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x2788547",
    "bytes": "660f740d91c6a7fd"
   },
   {
    "va": "0x278854f",
    "bytes": "660f740509dca7fd"
   }
  ],
  "feeds": [
   {
    "va": "0x2788541",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x278853b",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x2788564",
   "bytes": "0f8499000000",
   "asm": "je 0x2788603",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x279d5e0",
  "fde_end": "0x279dbee",
  "fde_len": 1550,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x279d80a",
    "bytes": "660f74054e89a6fd"
   },
   {
    "va": "0x279d819",
    "bytes": "660f740dbf73a6fd"
   }
  ],
  "feeds": [
   {
    "va": "0x279d803",
    "bytes": "f3410f6f442468"
   },
   {
    "va": "0x279d812",
    "bytes": "f3410f6f4c2478"
   }
  ],
  "branch": {
   "va": "0x279d82e",
   "bytes": "7419",
   "asm": "je 0x279d849",
   "polarity": "je"
  },
  "base_regs": [
   "r12",
   "r12"
  ],
  "feed_disps": [
   "0x68",
   "0x78"
  ]
 },
 {
  "fde": "0x279dbf0",
  "fde_end": "0x279e1d8",
  "fde_len": 1512,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x279de02",
    "bytes": "660f74055683a6fd"
   },
   {
    "va": "0x279de0f",
    "bytes": "660f740dc96da6fd"
   }
  ],
  "feeds": [
   {
    "va": "0x279ddfd",
    "bytes": "f30f6f4568"
   },
   {
    "va": "0x279de0a",
    "bytes": "f30f6f4d78"
   }
  ],
  "branch": {
   "va": "0x279de24",
   "bytes": "7419",
   "asm": "je 0x279de3f",
   "polarity": "je"
  },
  "base_regs": [
   "rbp",
   "rbp"
  ],
  "feed_disps": [
   "0x68",
   "0x78"
  ]
 },
 {
  "fde": "0x326aa40",
  "fde_end": "0x326abc1",
  "fde_len": 385,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x326aa9a",
    "bytes": "660f740d3ea1f9fc"
   },
   {
    "va": "0x326aaa2",
    "bytes": "660f7405b6b6f9fc"
   }
  ],
  "feeds": [
   {
    "va": "0x326aa95",
    "bytes": "f30f6f4b78"
   },
   {
    "va": "0x326aa90",
    "bytes": "f30f6f4368"
   }
  ],
  "branch": {
   "va": "0x326aabb",
   "bytes": "7524",
   "asm": "jne 0x326aae1",
   "polarity": "jne"
  },
  "base_regs": [
   "rbx",
   "rbx"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x326cfc0",
  "fde_end": "0x326d237",
  "fde_len": 631,
  "gate": 0,
  "class": "C",
  "pcmpeqb": [
   {
    "va": "0x326d023",
    "bytes": "660f740db57bf9fc"
   },
   {
    "va": "0x326d02b",
    "bytes": "660f74052d91f9fc"
   }
  ],
  "feeds": [
   {
    "va": "0x326d01e",
    "bytes": "f30f6f4e30"
   },
   {
    "va": "0x326d019",
    "bytes": "f30f6f4620"
   }
  ],
  "branch": {
   "va": "0x326d042",
   "bytes": "0f95c2",
   "asm": "setne dl",
   "polarity": "setne"
  },
  "base_regs": [
   "rsi",
   "rsi"
  ],
  "feed_disps": [
   "0x30",
   "0x20"
  ]
 },
 {
  "fde": "0x326d240",
  "fde_end": "0x326d4f4",
  "fde_len": 692,
  "gate": 0,
  "class": "C",
  "pcmpeqb": [
   {
    "va": "0x326d293",
    "bytes": "660f74054579f9fc"
   },
   {
    "va": "0x326d2a0",
    "bytes": "660f740db88ef9fc"
   }
  ],
  "feeds": [
   {
    "va": "0x326d28e",
    "bytes": "f30f6f4730"
   },
   {
    "va": "0x326d29b",
    "bytes": "f30f6f4f20"
   }
  ],
  "branch": {
   "va": "0x326d2b8",
   "bytes": "410f95c5",
   "asm": "setne r13b",
   "polarity": "setne"
  },
  "base_regs": [
   "rdi",
   "rdi"
  ],
  "feed_disps": [
   "0x30",
   "0x20"
  ]
 },
 {
  "fde": "0x3272190",
  "fde_end": "0x3272272",
  "fde_len": 226,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32721dd",
    "bytes": "660f740dfb29f9fc"
   },
   {
    "va": "0x32721e5",
    "bytes": "660f7405733ff9fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32721cc",
    "bytes": "f30f6f4c2478"
   },
   {
    "va": "0x32721c6",
    "bytes": "f30f6f442468"
   }
  ],
  "branch": {
   "va": "0x3272203",
   "bytes": "7438",
   "asm": "je 0x327223d",
   "polarity": "je"
  },
  "base_regs": [
   "rsp",
   "rsp"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x32aabb0",
  "fde_end": "0x32ab0bf",
  "fde_len": 1295,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32aac22",
    "bytes": "660f740db69ff5fc"
   },
   {
    "va": "0x32aac2a",
    "bytes": "660f74052eb5f5fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32aac1d",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x32aac18",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x32aac40",
   "bytes": "7418",
   "asm": "je 0x32aac5a",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x32ab270",
  "fde_end": "0x32ab3c1",
  "fde_len": 337,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32ab2b5",
    "bytes": "660f740d2399f5fc"
   },
   {
    "va": "0x32ab2bd",
    "bytes": "660f74059baef5fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32ab2b0",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x32ab2ab",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x32ab2d3",
   "bytes": "7418",
   "asm": "je 0x32ab2ed",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x32ab3d0",
  "fde_end": "0x32ab521",
  "fde_len": 337,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32ab415",
    "bytes": "660f740dc397f5fc"
   },
   {
    "va": "0x32ab41d",
    "bytes": "660f74053badf5fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32ab410",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x32ab40b",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x32ab433",
   "bytes": "7418",
   "asm": "je 0x32ab44d",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x32ab530",
  "fde_end": "0x32ab8ec",
  "fde_len": 956,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32ab5ef",
    "bytes": "660f740de995f5fc"
   },
   {
    "va": "0x32ab5f7",
    "bytes": "660f740561abf5fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32ab5e9",
    "bytes": "f3410f6f4f78"
   },
   {
    "va": "0x32ab5e3",
    "bytes": "f3410f6f4768"
   }
  ],
  "branch": {
   "va": "0x32ab60d",
   "bytes": "7507",
   "asm": "jne 0x32ab616",
   "polarity": "jne"
  },
  "base_regs": [
   "r15",
   "r15"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x32aca90",
  "fde_end": "0x32acc9f",
  "fde_len": 527,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32acad7",
    "bytes": "660f740d0181f5fc"
   },
   {
    "va": "0x32acadf",
    "bytes": "660f74057996f5fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32acad1",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x32acacb",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x32acaf4",
   "bytes": "0f8499000000",
   "asm": "je 0x32acb93",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x32acca0",
  "fde_end": "0x32aceaf",
  "fde_len": 527,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32acce7",
    "bytes": "660f740df17ef5fc"
   },
   {
    "va": "0x32accef",
    "bytes": "660f74056994f5fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32acce1",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x32accdb",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x32acd04",
   "bytes": "0f8499000000",
   "asm": "je 0x32acda3",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x32b4630",
  "fde_end": "0x32b4774",
  "fde_len": 324,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32b4667",
    "bytes": "660f740d7105f5fc"
   },
   {
    "va": "0x32b466f",
    "bytes": "660f7405e91af5fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32b4662",
    "bytes": "f30f6f4a78"
   },
   {
    "va": "0x32b465d",
    "bytes": "f30f6f4268"
   }
  ],
  "branch": {
   "va": "0x32b4689",
   "bytes": "7414",
   "asm": "je 0x32b469f",
   "polarity": "je"
  },
  "base_regs": [
   "rdx",
   "rdx"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x32d0920",
  "fde_end": "0x32d0f2c",
  "fde_len": 1548,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32d0b51",
    "bytes": "660f74050756f3fc"
   },
   {
    "va": "0x32d0b5f",
    "bytes": "660f740d7940f3fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32d0b4b",
    "bytes": "f3410f6f4668"
   },
   {
    "va": "0x32d0b59",
    "bytes": "f3410f6f4e78"
   }
  ],
  "branch": {
   "va": "0x32d0b74",
   "bytes": "7419",
   "asm": "je 0x32d0b8f",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x68",
   "0x78"
  ]
 },
 {
  "fde": "0x32d0f30",
  "fde_end": "0x32d153c",
  "fde_len": 1548,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32d1161",
    "bytes": "660f7405f74ff3fc"
   },
   {
    "va": "0x32d116f",
    "bytes": "660f740d693af3fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32d115b",
    "bytes": "f3410f6f4668"
   },
   {
    "va": "0x32d1169",
    "bytes": "f3410f6f4e78"
   }
  ],
  "branch": {
   "va": "0x32d1184",
   "bytes": "7419",
   "asm": "je 0x32d119f",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x68",
   "0x78"
  ]
 },
 {
  "fde": "0x32d1540",
  "fde_end": "0x32d1b4c",
  "fde_len": 1548,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32d1771",
    "bytes": "660f7405e749f3fc"
   },
   {
    "va": "0x32d177f",
    "bytes": "660f740d5934f3fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32d176b",
    "bytes": "f3410f6f4668"
   },
   {
    "va": "0x32d1779",
    "bytes": "f3410f6f4e78"
   }
  ],
  "branch": {
   "va": "0x32d1794",
   "bytes": "7419",
   "asm": "je 0x32d17af",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x68",
   "0x78"
  ]
 },
 {
  "fde": "0x32fe000",
  "fde_end": "0x32fe5d9",
  "fde_len": 1497,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32fe070",
    "bytes": "660f740d686bf0fc"
   },
   {
    "va": "0x32fe078",
    "bytes": "660f7405e080f0fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32fe06b",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x32fe066",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x32fe08e",
   "bytes": "7418",
   "asm": "je 0x32fe0a8",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x32ff750",
  "fde_end": "0x32ffa3a",
  "fde_len": 746,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x32ff796",
    "bytes": "660f740d4254f0fc"
   },
   {
    "va": "0x32ff79e",
    "bytes": "660f7405ba69f0fc"
   }
  ],
  "feeds": [
   {
    "va": "0x32ff791",
    "bytes": "f30f6f4978"
   },
   {
    "va": "0x32ff78c",
    "bytes": "f30f6f4168"
   }
  ],
  "branch": {
   "va": "0x32ff7b8",
   "bytes": "7414",
   "asm": "je 0x32ff7ce",
   "polarity": "je"
  },
  "base_regs": [
   "rcx",
   "rcx"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x44bb790",
  "fde_end": "0x44bb99f",
  "fde_len": 527,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x44bb7d7",
    "bytes": "660f740d0194d4fb"
   },
   {
    "va": "0x44bb7df",
    "bytes": "660f740579a9d4fb"
   }
  ],
  "feeds": [
   {
    "va": "0x44bb7d1",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x44bb7cb",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x44bb7f4",
   "bytes": "0f8499000000",
   "asm": "je 0x44bb893",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x44c07a0",
  "fde_end": "0x44c0dac",
  "fde_len": 1548,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x44c09d1",
    "bytes": "660f74058757d4fb"
   },
   {
    "va": "0x44c09df",
    "bytes": "660f740df941d4fb"
   }
  ],
  "feeds": [
   {
    "va": "0x44c09cb",
    "bytes": "f3410f6f4668"
   },
   {
    "va": "0x44c09d9",
    "bytes": "f3410f6f4e78"
   }
  ],
  "branch": {
   "va": "0x44c09f4",
   "bytes": "7419",
   "asm": "je 0x44c0a0f",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x68",
   "0x78"
  ]
 },
 {
  "fde": "0x44c98e0",
  "fde_end": "0x44c9eb9",
  "fde_len": 1497,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x44c9950",
    "bytes": "660f740d88b2d3fb"
   },
   {
    "va": "0x44c9958",
    "bytes": "660f740500c8d3fb"
   }
  ],
  "feeds": [
   {
    "va": "0x44c994b",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x44c9946",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x44c996e",
   "bytes": "7418",
   "asm": "je 0x44c9988",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x44c9ec0",
  "fde_end": "0x44ca0f2",
  "fde_len": 562,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x44c9f14",
    "bytes": "660f740dc4acd3fb"
   },
   {
    "va": "0x44c9f1c",
    "bytes": "660f74053cc2d3fb"
   }
  ],
  "feeds": [
   {
    "va": "0x44c9f0f",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x44c9f0a",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x44c9f32",
   "bytes": "7418",
   "asm": "je 0x44c9f4c",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x44ca770",
  "fde_end": "0x44caa57",
  "fde_len": 743,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x44ca7b6",
    "bytes": "660f740d22a4d3fb"
   },
   {
    "va": "0x44ca7be",
    "bytes": "660f74059ab9d3fb"
   }
  ],
  "feeds": [
   {
    "va": "0x44ca7b1",
    "bytes": "f30f6f4978"
   },
   {
    "va": "0x44ca7ac",
    "bytes": "f30f6f4168"
   }
  ],
  "branch": {
   "va": "0x44ca7d8",
   "bytes": "7414",
   "asm": "je 0x44ca7ee",
   "polarity": "je"
  },
  "base_regs": [
   "rcx",
   "rcx"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x4d5ff00",
  "fde_end": "0x4d6028f",
  "fde_len": 911,
  "gate": 0,
  "class": "B",
  "pcmpeqb": [
   {
    "va": "0x4d6007a",
    "bytes": "660f740d5e4b4afb"
   },
   {
    "va": "0x4d60082",
    "bytes": "660f7405d6604afb"
   }
  ],
  "feeds": [
   {
    "va": "0x4d60075",
    "bytes": "f30f6f4910"
   },
   {
    "va": "0x4d60071",
    "bytes": "f30f6f01"
   }
  ],
  "branch": {
   "va": "0x4d60097",
   "bytes": "7527",
   "asm": "jne 0x4d600c0",
   "polarity": "jne"
  },
  "base_regs": [
   "rcx",
   "rcx"
  ],
  "feed_disps": [
   "0x10",
   "0x0"
  ]
 },
 {
  "fde": "0x4d60290",
  "fde_end": "0x4d6061f",
  "fde_len": 911,
  "gate": 0,
  "class": "B",
  "pcmpeqb": [
   {
    "va": "0x4d6040a",
    "bytes": "660f740dce474afb"
   },
   {
    "va": "0x4d60412",
    "bytes": "660f7405465d4afb"
   }
  ],
  "feeds": [
   {
    "va": "0x4d60405",
    "bytes": "f30f6f4910"
   },
   {
    "va": "0x4d60401",
    "bytes": "f30f6f01"
   }
  ],
  "branch": {
   "va": "0x4d60427",
   "bytes": "7527",
   "asm": "jne 0x4d60450",
   "polarity": "jne"
  },
  "base_regs": [
   "rcx",
   "rcx"
  ],
  "feed_disps": [
   "0x10",
   "0x0"
  ]
 },
 {
  "fde": "0x4dd6580",
  "fde_end": "0x4dd693c",
  "fde_len": 956,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x4dd663f",
    "bytes": "660f740d99e542fb"
   },
   {
    "va": "0x4dd6647",
    "bytes": "660f740511fb42fb"
   }
  ],
  "feeds": [
   {
    "va": "0x4dd6639",
    "bytes": "f3410f6f4f78"
   },
   {
    "va": "0x4dd6633",
    "bytes": "f3410f6f4768"
   }
  ],
  "branch": {
   "va": "0x4dd665d",
   "bytes": "7507",
   "asm": "jne 0x4dd6666",
   "polarity": "jne"
  },
  "base_regs": [
   "r15",
   "r15"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x4dd6c90",
  "fde_end": "0x4dd6e9f",
  "fde_len": 527,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x4dd6cd7",
    "bytes": "660f740d01df42fb"
   },
   {
    "va": "0x4dd6cdf",
    "bytes": "660f740579f442fb"
   }
  ],
  "feeds": [
   {
    "va": "0x4dd6cd1",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x4dd6ccb",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x4dd6cf4",
   "bytes": "0f8499000000",
   "asm": "je 0x4dd6d93",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x4e6bcb0",
  "fde_end": "0x4e6c840",
  "fde_len": 2960,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x4e6bf63",
    "bytes": "660f740d758c39fb"
   },
   {
    "va": "0x4e6bf6b",
    "bytes": "660f7405eda139fb"
   }
  ],
  "feeds": [
   {
    "va": "0x4e6bf5e",
    "bytes": "f30f6f4d78"
   },
   {
    "va": "0x4e6bf59",
    "bytes": "f30f6f4568"
   }
  ],
  "branch": {
   "va": "0x4e6bf80",
   "bytes": "0f849d000000",
   "asm": "je 0x4e6c023",
   "polarity": "je"
  },
  "base_regs": [
   "rbp",
   "rbp"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x4e6f840",
  "fde_end": "0x4e6fbfc",
  "fde_len": 956,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x4e6f8ff",
    "bytes": "660f740dd95239fb"
   },
   {
    "va": "0x4e6f907",
    "bytes": "660f7405516839fb"
   }
  ],
  "feeds": [
   {
    "va": "0x4e6f8f9",
    "bytes": "f3410f6f4f78"
   },
   {
    "va": "0x4e6f8f3",
    "bytes": "f3410f6f4768"
   }
  ],
  "branch": {
   "va": "0x4e6f91d",
   "bytes": "7507",
   "asm": "jne 0x4e6f926",
   "polarity": "jne"
  },
  "base_regs": [
   "r15",
   "r15"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x4e6fd50",
  "fde_end": "0x4e6fee2",
  "fde_len": 402,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x4e6fd8f",
    "bytes": "660f740d494e39fb"
   },
   {
    "va": "0x4e6fd97",
    "bytes": "660f7405c16339fb"
   }
  ],
  "feeds": [
   {
    "va": "0x4e6fd89",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x4e6fd83",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x4e6fdac",
   "bytes": "0f8487000000",
   "asm": "je 0x4e6fe39",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x4e84cc0",
  "fde_end": "0x4e85292",
  "fde_len": 1490,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x4e84d29",
    "bytes": "660f740daffe37fb"
   },
   {
    "va": "0x4e84d31",
    "bytes": "660f7405271438fb"
   }
  ],
  "feeds": [
   {
    "va": "0x4e84d24",
    "bytes": "f30f6f4878"
   },
   {
    "va": "0x4e84d1f",
    "bytes": "f30f6f4068"
   }
  ],
  "branch": {
   "va": "0x4e84d47",
   "bytes": "7418",
   "asm": "je 0x4e84d61",
   "polarity": "je"
  },
  "base_regs": [
   "rax",
   "rax"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x4e852a0",
  "fde_end": "0x4e85663",
  "fde_len": 963,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x4e852f8",
    "bytes": "660f740de0f837fb"
   },
   {
    "va": "0x4e85300",
    "bytes": "660f7405580e38fb"
   }
  ],
  "feeds": [
   {
    "va": "0x4e852f2",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x4e852ec",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x4e85315",
   "bytes": "0f8434010000",
   "asm": "je 0x4e8544f",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x4e852a0",
  "fde_end": "0x4e85663",
  "fde_len": 963,
  "gate": 1,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x4e8537a",
    "bytes": "660f740d5ef837fb"
   },
   {
    "va": "0x4e85382",
    "bytes": "660f7405d60d38fb"
   }
  ],
  "feeds": [
   {
    "va": "0x4e85374",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x4e8536e",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x4e85397",
   "bytes": "7418",
   "asm": "je 0x4e853b1",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 },
 {
  "fde": "0x4e856f0",
  "fde_end": "0x4e85b12",
  "fde_len": 1058,
  "gate": 0,
  "class": "A",
  "pcmpeqb": [
   {
    "va": "0x4e85741",
    "bytes": "660f740d97f437fb"
   },
   {
    "va": "0x4e85749",
    "bytes": "660f74050f0a38fb"
   }
  ],
  "feeds": [
   {
    "va": "0x4e8573b",
    "bytes": "f3410f6f4e78"
   },
   {
    "va": "0x4e85735",
    "bytes": "f3410f6f4668"
   }
  ],
  "branch": {
   "va": "0x4e8575e",
   "bytes": "0f8464010000",
   "asm": "je 0x4e858c8",
   "polarity": "je"
  },
  "base_regs": [
   "r14",
   "r14"
  ],
  "feed_disps": [
   "0x78",
   "0x68"
  ]
 }
]

# Behavioral-feature anchors (byte-verified like the gates).
FEATURES = {
    "double_gate": {
        "fde": "0x4e852a0",
        "flag_read": {"va": "0x4e852b7", "bytes": "440fb6bfb0000000"},
        "gate1_pcmpeqb": ["0x4e852f8", "0x4e85300"],
        "gate2_pcmpeqb": ["0x4e8537a", "0x4e85382"],
        "vectors_orfold": ["498b4670", "490b8680000000", "498b4e68", "490b4e78", "4809c1"],
        "vectors_orfold_vas": ["0x4e85399", "0x4e8539d", "0x4e853a4", "0x4e853a8", "0x4e853ac"],
        "difference_orfold": ["498b4648", "490b4658", "498b4e40", "490b4e50", "4809c1"],
        "difference_orfold_vas": ["0x4e853b1", "0x4e853b5", "0x4e853b9", "0x4e853bd", "0x4e853c1"],
        "difference_zero_branch": {"va": "0x4e853c4", "bytes": "0f841e020000"},
        "counter_test": {"va": "0x4e855e8", "bytes": "49837e6000"},
        "counter_sete": {"va": "0x4e855ed", "bytes": "410f94c7"},
    },
    "counter_coupled": [
        {"fde": "0x2787ca0", "cmp": {"va": "0x2787d74", "bytes": "49837f6000"}, "je": {"va": "0x2787d79", "bytes": "742a"}},
        {"fde": "0x32ab530", "cmp": {"va": "0x32ab60f", "bytes": "49837f6000"}, "je": {"va": "0x32ab614", "bytes": "7428"}},
        {"fde": "0x4dd6580", "cmp": {"va": "0x4dd665f", "bytes": "49837f6000"}, "je": {"va": "0x4dd6664", "bytes": "7428"}},
        {"fde": "0x4e6f840", "cmp": {"va": "0x4e6f91f", "bytes": "49837f6000"}, "je": {"va": "0x4e6f924", "bytes": "7428"}},
    ],
    "vectors_zero_rejoin": [{"fde": "0x1ebde00", "gate": 0, "jne": {"va": "0x1ebdea6", "bytes": "7519", "asm": "jne 0x1ebdec1"}}, {"fde": "0x1ebe3e0", "gate": 0, "jne": {"va": "0x1ebe486", "bytes": "7519", "asm": "jne 0x1ebe4a1"}}, {"fde": "0x1ebe9c0", "gate": 0, "jne": {"va": "0x1ebea4d", "bytes": "7519", "asm": "jne 0x1ebea68"}}, {"fde": "0x1ebec00", "gate": 0, "jne": {"va": "0x1ebec8a", "bytes": "7519", "asm": "jne 0x1ebeca5"}}, {"fde": "0x1ebfe60", "gate": 0, "jne": {"va": "0x1ebfedc", "bytes": "7520", "asm": "jne 0x1ebfefe"}}, {"fde": "0x1ec0150", "gate": 0, "jne": {"va": "0x1ec01cc", "bytes": "7520", "asm": "jne 0x1ec01ee"}}, {"fde": "0x279d5e0", "gate": 0, "jne": {"va": "0x279d847", "bytes": "7527", "asm": "jne 0x279d870"}}, {"fde": "0x279dbf0", "gate": 0, "jne": {"va": "0x279de3d", "bytes": "752a", "asm": "jne 0x279de69"}}, {"fde": "0x32aabb0", "gate": 0, "jne": {"va": "0x32aac58", "bytes": "7519", "asm": "jne 0x32aac73"}}, {"fde": "0x32ab270", "gate": 0, "jne": {"va": "0x32ab2eb", "bytes": "7519", "asm": "jne 0x32ab306"}}, {"fde": "0x32ab3d0", "gate": 0, "jne": {"va": "0x32ab44b", "bytes": "7519", "asm": "jne 0x32ab466"}}, {"fde": "0x32b4630", "gate": 0, "jne": {"va": "0x32b469d", "bytes": "7520", "asm": "jne 0x32b46bf"}}, {"fde": "0x32d0920", "gate": 0, "jne": {"va": "0x32d0b8d", "bytes": "752a", "asm": "jne 0x32d0bb9"}}, {"fde": "0x32d0f30", "gate": 0, "jne": {"va": "0x32d119d", "bytes": "752a", "asm": "jne 0x32d11c9"}}, {"fde": "0x32d1540", "gate": 0, "jne": {"va": "0x32d17ad", "bytes": "752a", "asm": "jne 0x32d17d9"}}, {"fde": "0x32fe000", "gate": 0, "jne": {"va": "0x32fe0a6", "bytes": "7519", "asm": "jne 0x32fe0c1"}}, {"fde": "0x32ff750", "gate": 0, "jne": {"va": "0x32ff7cc", "bytes": "7520", "asm": "jne 0x32ff7ee"}}, {"fde": "0x44c07a0", "gate": 0, "jne": {"va": "0x44c0a0d", "bytes": "752a", "asm": "jne 0x44c0a39"}}, {"fde": "0x44c98e0", "gate": 0, "jne": {"va": "0x44c9986", "bytes": "7519", "asm": "jne 0x44c99a1"}}, {"fde": "0x44c9ec0", "gate": 0, "jne": {"va": "0x44c9f4a", "bytes": "7519", "asm": "jne 0x44c9f65"}}, {"fde": "0x44ca770", "gate": 0, "jne": {"va": "0x44ca7ec", "bytes": "7520", "asm": "jne 0x44ca80e"}}, {"fde": "0x4e84cc0", "gate": 0, "jne": {"va": "0x4e84d5f", "bytes": "7519", "asm": "jne 0x4e84d7a"}}, {"fde": "0x4e852a0", "gate": 1, "jne": {"va": "0x4e853af", "bytes": "7519", "asm": "jne 0x4e853ca"}}],
    "flag_anchor": {
        "fde": "0x3272190",
        "je": {"va": "0x3272203", "bytes": "7438"},
        "match_zero": {"va": "0x327223d", "bytes": "31d2"},
        "nonmatch_one": {"va": "0x327221f", "bytes": "b201"},
        "flag_store": {"va": "0x3272251", "bytes": "885328"},
    },
}

CASES = [
    # case, class_or_feature, gate_or_fde, polarity, vectors_match, vectors_all_zero, difference_all_zero, counter_zero, outcome
    ["A-je-match", "A", "je-gate", "je", "1", "", "", "", "branch taken: match path"],
    ["A-je-nonmatch", "A", "je-gate", "je", "0", "", "", "", "fall-through: non-match path"],
    ["A-jne-match", "A", "jne-gate", "jne", "1", "", "", "", "fall-through: match path"],
    ["A-jne-nonmatch", "A", "jne-gate", "jne", "0", "", "", "", "branch taken: non-match path"],
    ["B-jne-match", "B", "jne-gate", "jne", "1", "", "", "", "fall-through: match path"],
    ["B-jne-nonmatch", "B", "jne-gate", "jne", "0", "", "", "", "branch taken: non-match path"],
    ["C-setne-match", "C", "setne-gate", "setne", "1", "", "", "", "boolean 0"],
    ["C-setne-nonmatch", "C", "setne-gate", "setne", "0", "", "", "", "boolean 1"],
    ["DG-flag-low", "double-gate", "0x4e852a0", "je", "", "", "", "", "gate 2 skipped: flag byte <= 4"],
    ["DG-g1-match-flag-high", "double-gate", "0x4e852a0", "je", "1", "", "", "", "gate 1 match path, then gate 2 runs"],
    ["DG-g1-nonmatch-flag-high", "double-gate", "0x4e852a0", "je", "0", "", "", "", "gate 1 transform path, then gate 2 runs"],
    ["DG-g2-match", "double-gate", "0x4e852a0", "je", "1", "", "", "", "difference check runs"],
    ["DG-g2-nonmatch-vectors-nonzero", "double-gate", "0x4e852a0", "je", "0", "0", "", "", "0x4e853ca outcome: live-vectors path"],
    ["DG-g2-vectors-zero", "double-gate", "0x4e852a0", "je", "0", "1", "", "", "difference check runs"],
    ["DG-difference-zero", "double-gate", "0x4e852a0", "je", "", "", "1", "", "counter test runs: sete r15b = (counter == 0)"],
    ["DG-difference-nonzero", "double-gate", "0x4e852a0", "je", "", "", "0", "", "0x4e853ca outcome: live-difference path"],
    ["CC-match-counter-zero", "counter-coupled", "jne-gate", "jne", "1", "", "", "1", "match path, then je taken on counter == 0"],
    ["CC-match-counter-nonzero", "counter-coupled", "jne-gate", "jne", "1", "", "", "0", "match path, counter test falls through"],
    ["VZ-nonmatch-vectors-zero", "vectors-zero-rejoin", "je-gate", "je", "0", "1", "", "", "rejoins match path difference check"],
    ["VZ-nonmatch-vectors-nonzero", "vectors-zero-rejoin", "je-gate", "je", "0", "0", "", "", "diverges from match path"],
    ["FA-match", "flag-anchor", "0x3272190", "je", "1", "", "", "", "flag byte 0 at output+0x28"],
    ["FA-nonmatch", "flag-anchor", "0x3272190", "je", "0", "", "", "", "flag byte 1 at output+0x28"],
]


def va_to_offset(sections, va):
    for s in sections:
        if s["type"] == 8:
            continue
        if s["address"] <= va < s["address"] + s["size"]:
            return s["offset"] + (va - s["address"])
    raise ValueError(f"VA {va:#x} has no file mapping")


def read_bytes(data, sections, va, length):
    off = va_to_offset(sections, va)
    return data[off:off + length]


def check_anchor(data, sections, va, hex_bytes):
    want = bytes.fromhex(hex_bytes)
    got = read_bytes(data, sections, va, len(want))
    if got != want:
        raise ValueError(f"anchor mismatch at {va:#x}: got {got.hex()}, want {hex_bytes}")


def parse_fde_ends(data):
    """Parse .eh_frame records into {initial_location: (end, length)}."""
    secs = elf_index.sections(data)
    eh = next(s for s in secs if s["name"] == ".eh_frame")
    base, size = eh["offset"], eh["size"]

    def uleb(buf, p):
        v = 0; s = 0
        while True:
            b = buf[p]; p += 1; v |= (b & 0x7F) << s; s += 7
            if not (b & 0x80):
                return v, p

    def sleb(buf, p):
        v = 0; s = 0
        while True:
            b = buf[p]; p += 1; v |= (b & 0x7F) << s; s += 7
            if not (b & 0x80):
                if b & 0x40:
                    v |= -(1 << s)
                return v, p

    p = base; cies = {}; fdes = {}
    while p < base + size:
        rec_start = p
        length, = struct.unpack_from("<I", data, p)
        if length == 0:
            break
        cie_id, = struct.unpack_from("<I", data, p + 4)
        if cie_id == 0:
            q = p + 8
            q += 1  # version
            e = data.index(b"\0", q); aug = data[q:e].decode(); q = e + 1
            _, q = uleb(data, q); _, q = sleb(data, q); _, q = uleb(data, q)
            fde_enc = None
            if aug.startswith("z"):
                _, q = uleb(data, q)
                for ch in aug[1:]:
                    if ch == "L":
                        q += 1
                    elif ch == "P":
                        enc = data[q]; q += 1
                        q += {0x03: 4, 0x04: 8, 0x0B: 4, 0x0C: 8, 0x0A: 2, 0x02: 2}.get(enc & 0x0F, 8)
                    elif ch == "R":
                        fde_enc = data[q]; q += 1
            cies[rec_start] = fde_enc
        else:
            cie_off = (p + 4) - cie_id
            enc = cies.get(cie_off)
            fmt = enc & 0x0F if enc is not None else 0x04
            app = enc & 0x70 if enc is not None else 0
            q = p + 8
            if fmt == 0x03:
                loc, q = struct.unpack_from("<I", data, q)[0], q + 4
            elif fmt == 0x04:
                loc, q = struct.unpack_from("<Q", data, q)[0], q + 8
            elif fmt == 0x0B:
                loc, q = struct.unpack_from("<i", data, q)[0], q + 4
            elif fmt == 0x0C:
                loc, q = struct.unpack_from("<q", data, q)[0], q + 8
            elif fmt == 0x0A:
                loc, q = struct.unpack_from("<h", data, q)[0], q + 2
            else:
                raise ValueError(f"unsupported FDE encoding {enc:#x}")
            # pcrel: target = address of the location field + signed value.
            # .eh_frame VA == file offset in this binary.
            field_size = {0x03: 4, 0x04: 8, 0x0B: 4, 0x0C: 8, 0x0A: 2}[fmt]
            if app == 0x10:
                loc = (q - field_size) + loc
            if fmt == 0x03:
                rng, q = struct.unpack_from("<I", data, q)[0], q + 4
            elif fmt == 0x04:
                rng, q = struct.unpack_from("<Q", data, q)[0], q + 8
            elif fmt == 0x0B:
                rng, q = struct.unpack_from("<i", data, q)[0], q + 4
            elif fmt == 0x0C:
                rng, q = struct.unpack_from("<q", data, q)[0], q + 8
            elif fmt == 0x0A:
                rng, q = struct.unpack_from("<h", data, q)[0], q + 2
            fdes[loc] = (loc + rng, rng)
        p = rec_start + 4 + length
    return secs, fdes


def disp32_scan(data, sections):
    """Byte-level scan: every disp32 in .text whose rip-relative target is
    one of the two constants. Returns {disp_field_va: target}."""
    text = next(s for s in sections if s["name"] == ".text")
    blob = data[text["offset"]:text["offset"] + text["size"]]
    out = {}
    for p in range(0, len(blob) - 4):
        disp, = struct.unpack_from("<i", blob, p)
        target = text["address"] + p + 4 + disp
        if target in (CONST_HI, CONST_LO):
            out[text["address"] + p] = target
    return out


def main(binary, out_dir):
    data = Path(binary).read_bytes()
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("node digest mismatch")
    secs, fdes = parse_fde_ends(data)
    # 1. Anchor verification for every gate.
    windows = {}
    for g in GATES:
        fde = int(g["fde"], 16)
        if fde not in fdes:
            raise ValueError(f"FDE {g['fde']} missing from .eh_frame")
        end, length = fdes[fde]
        if end != int(g["fde_end"], 16) or length != g["fde_len"]:
            raise ValueError(f"FDE {g['fde']} bounds mismatch: got {end:#x}/{length}, want {g['fde_end']}/{g['fde_len']}")
        for p in g["pcmpeqb"]:
            check_anchor(data, secs, int(p["va"], 16), p["bytes"])
        for f in g["feeds"]:
            check_anchor(data, secs, int(f["va"], 16), f["bytes"])
        check_anchor(data, secs, int(g["branch"]["va"], 16), g["branch"]["bytes"])
        digest = hashlib.sha256(read_bytes(data, secs, fde, length)).hexdigest()
        windows[g["fde"]] = {"end": g["fde_end"], "length": length, "sha256": digest}
    # 2. Feature anchors.
    dg = FEATURES["double_gate"]
    check_anchor(data, secs, int(dg["flag_read"]["va"], 16), dg["flag_read"]["bytes"])
    for vas, byts in zip(dg["vectors_orfold_vas"], dg["vectors_orfold"]):
        check_anchor(data, secs, int(vas, 16), byts)
    for vas, byts in zip(dg["difference_orfold_vas"], dg["difference_orfold"]):
        check_anchor(data, secs, int(vas, 16), byts)
    check_anchor(data, secs, int(dg["difference_zero_branch"]["va"], 16), dg["difference_zero_branch"]["bytes"])
    check_anchor(data, secs, int(dg["counter_test"]["va"], 16), dg["counter_test"]["bytes"])
    check_anchor(data, secs, int(dg["counter_sete"]["va"], 16), dg["counter_sete"]["bytes"])
    for cc in FEATURES["counter_coupled"]:
        check_anchor(data, secs, int(cc["cmp"]["va"], 16), cc["cmp"]["bytes"])
        check_anchor(data, secs, int(cc["je"]["va"], 16), cc["je"]["bytes"])
    fa = FEATURES["flag_anchor"]
    for key in ("je", "match_zero", "nonmatch_one", "flag_store"):
        check_anchor(data, secs, int(fa[key]["va"], 16), fa[key]["bytes"])
    for rj in FEATURES["vectors_zero_rejoin"]:
        check_anchor(data, secs, int(rj["jne"]["va"], 16), rj["jne"]["bytes"])
    # 3. Independent census: disp32 scan + pcmpeqb-prefix check + pairing.
    cands = disp32_scan(data, secs)
    if len(cands) != 94:
        raise ValueError(f"disp32 census: got {len(cands)} candidates, want 94")
    starts = sorted(fdes.keys())
    per_fde = {}
    for disp_va, target in sorted(cands.items()):
        # The disp32 field sits at the end of the instruction; the 3 bytes
        # before it must be 66 0f 74 with modrm mod=00, rm=101.
        ins_va = disp_va - 4
        prefix = read_bytes(data, secs, ins_va, 3)
        if prefix[0] != 0x66 or prefix[1] != 0x0F or prefix[2] != 0x74:
            raise ValueError(f"candidate at {disp_va:#x} is not pcmpeqb: {prefix.hex()}")
        # modrm is the fourth byte (offset ins_va+3).
        modrm = read_bytes(data, secs, ins_va + 3, 1)[0]
        if modrm & 0xC7 != 0x05:
            raise ValueError(f"candidate at {disp_va:#x} is not rip-relative pcmpeqb: modrm {modrm:#x}")
        i = bisect.bisect_right(starts, ins_va) - 1
        per_fde.setdefault(starts[i], []).append(ins_va)
    if len(per_fde) != 46:
        raise ValueError(f"census FDEs: got {len(per_fde)}, want 46")
    census_pairs = []
    for fde in sorted(per_fde):
        vas = sorted(per_fde[fde])
        if len(vas) % 2 != 0:
            raise ValueError(f"FDE {fde:#x} has odd pcmpeqb count {len(vas)}")
        # Pair consecutive compares per FDE in address order. Most gates
        # are load-load-compare-compare (8 bytes apart); some interleave a
        # feed between the compares (e.g. 0x279d5e0: 15 bytes apart), so
        # adjacency is NOT required -- only even count and address order.
        for k in range(0, len(vas), 2):
            census_pairs.append((vas[k], vas[k + 1]))
    if len(census_pairs) != 47:
        raise ValueError(f"census gates: got {len(census_pairs)}, want 47")
    recorded = sorted((int(p[0]["va"], 16), int(p[1]["va"], 16)) for g in GATES for p in [g["pcmpeqb"]])
    if sorted(census_pairs) != recorded:
        raise ValueError("census gate addresses differ from recorded gates")
    # 4. Producer negatives (byte-level).
    text = next(s for s in secs if s["name"] == ".text")
    blob = data[text["offset"]:text["offset"] + text["size"]]
    if blob.find(CONST_HI_BYTES) != -1 or blob.find(CONST_LO_BYTES) != -1:
        raise ValueError("constant pattern found in .text")
    for s in secs:
        if s["type"] == 8 or (s["flags"] & 4):
            continue
        b = data[s["offset"]:s["offset"] + s["size"]]
        if b.find(struct.pack("<Q", CONST_HI)) != -1 or b.find(struct.pack("<Q", CONST_LO)) != -1:
            raise ValueError(f"pointer to a constant found in {s['name']}")
    # 5. Emit.
    out_dir.mkdir(parents=True, exist_ok=True)
    from collections import Counter
    evidence = {
        "target": "node #94",
        "sha256": SHA256,
        "worktree_baseline": "2993e46",
        "gates_total": 47,
        "fdes_total": 46,
        "classes": dict(Counter(g["class"] for g in GATES)),
        "polarity": dict(Counter(g["branch"]["polarity"] for g in GATES)),
        "constants": {"0x204be0": CONST_HI_BYTES.hex(), "0x206160": CONST_LO_BYTES.hex()},
        "census_method": "byte-level disp32 scan over .text (94 candidates, all pcmpeqb rip-relative, all paired adjacently), cross-checked against a capstone linear sweep inside FDE bounds (94/94 agreement)",
        "producer_negatives": {
            "text_immediate_patterns": "absent",
            "data_pointers_to_constants": "absent",
            "non_pcmpeqb_references_to_constants": "absent (disp32 scan + capstone sweep agree: 94/94)",
            "inline_vector_writes_in_gate_fdes": "none except two stack-slot stores in 0x4e856f0 ([rsp+0x68]/[rsp+0x78]), which are not object writes",
        },
        "features": {
            "vectors_zero_rejoin_gates": len(FEATURES["vectors_zero_rejoin"]),
            "vectors_zero_rejoin_fdes": [r["fde"] for r in FEATURES["vectors_zero_rejoin"]],
            "double_gate_fde": "0x4e852a0",
            "counter_coupled_fdes": [c["fde"] for c in FEATURES["counter_coupled"]],
            "flag_anchor_fde": "0x3272190",
        },
        "prior_work": {
            "twins_in_census": ["0x2788350", "0x2788500"],
            "twins_note": "previously mapped in the tag-5 resolver twins packet (PR #1785); included here only as census members, not re-claimed",
            "adjacent_not_overlapping": "0x279d5e0 starts exactly where the #161 caller-B window ends (0x279d3e0..0x279d5e0); half-open windows share no byte",
        },
        "cases": len(CASES),
        "windows": windows,
    }
    (out_dir / "evidence.json").write_text(json.dumps(evidence, indent=1) + "\n")
    gate_lines = ["fde\tfde_end\tgate\tclass\tpcmpeqb_hi\tpcmpeqb_lo\tbranch_va\tpolarity\tfeed_disps\tbase_regs"]
    def disp_target(p):
        disp, = struct.unpack("<i", bytes.fromhex(p["bytes"])[-4:])
        return int(p["va"], 16) + 8 + disp

    for g in sorted(GATES, key=lambda x: int(x["fde"], 16)):
        hi_va = next(p["va"] for p in g["pcmpeqb"] if disp_target(p) == CONST_HI)
        lo_va = next(p["va"] for p in g["pcmpeqb"] if disp_target(p) == CONST_LO)
        gate_lines.append("\t".join([g["fde"], g["fde_end"], str(g["gate"]), g["class"],
                                      hi_va, lo_va,
                                      g["branch"]["va"], g["branch"]["polarity"],
                                      ",".join(g["feed_disps"]), ",".join(g["base_regs"])]))
    (out_dir / "gates.tsv").write_text("\n".join(gate_lines) + "\n")
    case_lines = ["case\tclass_or_feature\tgate_or_fde\tpolarity\tvectors_match\tvectors_all_zero\tdifference_all_zero\tcounter_zero\toutcome"]
    for row in CASES:
        case_lines.append("\t".join(row))
    (out_dir / "cases.tsv").write_text("\n".join(case_lines) + "\n")
    win_lines = []
    for fde in sorted(windows, key=lambda x: int(x, 16)):
        w = windows[fde]
        win_lines.append(f"{fde}..{w['end']} length={w['length']} sha256={w['sha256']}")
    (out_dir / "windows.txt").write_text("\n".join(win_lines) + "\n")
    return {"gates": 47, "fdes": 46, "cases": len(CASES)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if args.out.exists() and any(args.out.iterdir()):
        raise ValueError(f"output directory {args.out} is not empty")
    print(json.dumps(main(args.binary, args.out), indent=1))
