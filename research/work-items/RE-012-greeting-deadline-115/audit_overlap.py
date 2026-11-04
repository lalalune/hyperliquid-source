"""Independent byte-overlap audit for the two selected sender input fields."""
import importlib.util
import json
from pathlib import Path
import sys

repo=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parents[3]
packet=repo/'research/work-items/RE-012-greeting-deadline-115'
spec=importlib.util.spec_from_file_location('deadline_audit',packet/'collect.py')
c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
sys.path.insert(0,str(repo/'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
import capstone
data=(repo/'artifacts/node/115/hl-node').read_bytes()
secs=sections(data);_,fdes=eh_frame_records(data,secs)
image=c.Image(data,secs,fdes)
cs=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);cs.detail=True
records=[]
for i in cs.disasm(image.read(0x2b7a290,4755),0x2b7a290):
    if i.mnemonic=='lea':
        continue
    for op in i.operands:
        if op.type==capstone.x86.X86_OP_MEM and op.mem.base==capstone.x86.X86_REG_RBX and op.size and op.mem.disp<0x68 and op.mem.disp+op.size>0x58:
            records.append({'va':hex(i.address),'offset':hex(op.mem.disp),'width':op.size,'access':op.access,'assembly':i.mnemonic+' '+i.op_str})
output={'selected_storage_interval':'[sender+0x58,sender+0x68)','records':records,
        'direct_writes':[r['va'] for r in records if r['access']&capstone.CS_AC_WRITE],
        'limits':'RBX-relative explicit memory operands only; dynamic alias and helper-effect closure is not established.'}
print(json.dumps(output,indent=2))
