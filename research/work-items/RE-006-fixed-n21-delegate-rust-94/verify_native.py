"""Authenticate fixed-n21 producer/caller bytes and finite operand controls."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
import struct
import subprocess
import tempfile

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
SHA='3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'


def sha(raw):return hashlib.sha256(raw).hexdigest()


def require(ok,reason):
    if not ok:raise ValueError(reason)


SUPPORT=ROOT/'research/work-items/RE-006-j9-first-front-rust-94/verify_native.py'
require(sha(SUPPORT.read_bytes())=='99adb98cb0558d57f8fcc5adc28156c9c2f6ea69d233f35a230786745efb2f8d','reviewed decoder support identity')
spec=importlib.util.spec_from_file_location('reviewed_native_image_support',SUPPORT)
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)


def decode(binary,data,lo,hi,llvm):
    image=V.Image(data);all_rows=[];streams=[]
    for command in [
        ['objdump','-d','-Mintel','--insn-width=16',f'--start-address={lo}',f'--stop-address={hi}',str(binary)],
        [str(llvm),'-d','--x86-asm-syntax=intel',f'--start-address={lo}',f'--stop-address={hi}',str(binary)],
    ]:
        p=subprocess.run(command,capture_output=True)
        require(p.returncode==0 and not p.stderr,'decoder exit/stderr')
        streams.append((p.stdout,p.stderr));rows=[];cursor=lo
        for line in p.stdout.decode().splitlines():
            match=V.LINE.match(line)
            if match:
                at=int(match[1],16);raw=bytes.fromhex(match[2])
                require(at==cursor and raw==image.read(at,len(raw)),'instruction byte partition')
                cursor+=len(raw);rows.append((at,raw,match[3]))
        require(cursor==hi,'complete body partition');all_rows.append(rows)
    require([(a,b) for a,b,_ in all_rows[0]]==[(a,b) for a,b,_ in all_rows[1]],'GNU/LLVM partition disagreement')
    return {a:(b,c) for a,b,c in all_rows[0]},streams


def verify(binary,llvm,out):
    require(not out.exists(),'fresh output required')
    data=binary.read_bytes();require(len(data)==91774280 and sha(data)==SHA,'target identity')
    image=V.Image(data);sections=V.sections(data);_,frames=V.eh_frame_records(data,sections)
    intake=(HERE/'seed/SEED-NATIVE-INTAKE.json').read_bytes()
    require(sha(intake)=='b12fad948c53b53fcf247dc5b92f9e61640608d6dace7bdb38045ec2ac016add','frozen native intake')
    expected=json.loads(intake);functions=[];body_rows={};out.mkdir(parents=True)
    for record in expected['functions']:
        lo,hi=int(record['start'],16),int(record['end'],16)
        hits=[f for f in frames if f['start']<=lo<f['end']]
        require(len(hits)==1 and hits[0]['start']==lo and hits[0]['end']==hi,'unique exact FDE')
        f=hits[0]
        require(sha(image.read(lo,hi-lo))==record['body_sha256'],'full body SHA')
        require(hex(f['fde'])==record['fde'] and image.record(f['fde'])==record['fde_hex'],'FDE bytes')
        require(hex(f['cie'])==record['cie'] and image.record(f['cie'])==record['cie_hex'],'CIE bytes')
        require((None if f['lsda'] is None else hex(f['lsda']))==record['lsda'],'LSDA binding')
        rows,streams=decode(binary,data,lo,hi,llvm);require(len(rows)==record['instructions'],'instruction denominator')
        body_rows[lo]=rows;functions.append(record)
        if lo in [0x4912a50,0x4918d30]:
            for tool,payloads in zip(['gnu','llvm'],streams):
                for kind,payload in zip(['stdout','stderr'],payloads):(out/f'{lo:x}.{tool}.{kind}').write_bytes(payload)
    for call in expected['selected_direct_calls']:
        site,target=int(call['site'],16),int(call['target'],16);raw=image.read(site,5)
        require(raw.hex()==call['bytes'] and raw[0]==0xe8 and site+5+struct.unpack('<i',raw[1:])[0]==target,'selected E8 binding')
    rela=next(s for s in sections if s['name']=='.rela.dyn')
    slots=[struct.unpack_from('<QQq',data,pos) for pos in range(rela['offset'],rela['offset']+rela['size'],24)]
    for site,slot,target in [(0x4dbd5d1,0x57768a0,0x4497a90),(0x4912d0d,0x576eaf8,0x157a6d0),(0x4919091,0x576eaf8,0x157a6d0)]:
        raw=image.read(site,6)
        require(raw[:2]==b'\xff\x15' and site+6+struct.unpack('<i',raw[2:])[0]==slot,'RIP call slot')
        require([r for r in slots if r[0]==slot]==[(slot,8,target)],'unique RELATIVE slot')
    controls=[]
    for path,digest in [('seed/SEED-PRE-SOURCE-NATIVE-CONTROLS.json','cac85ac4446c8434e5823d18995a6fb28cc60f0d01f164f4bf76a1dfbce9d458'),('prepared/PRE-SOURCE-NATIVE-CONTROLS.json','322e90bb31af21dc304ba73058e6f269c69515c6f2e8872a20f53138be2ed773')]:
        raw=(HERE/path).read_bytes();require(sha(raw)==digest,'pre-source operand control identity');controls+=json.loads(raw)['controls']
    def properties(rows):
        for control in controls:
            at=int(control['va'],16)
            if at in rows:require(re.sub(r'\s+',' ',rows[at][1])==control['expected_operand'],control['name'])
    properties(body_rows[0x4912a50]);properties(body_rows[0x4918d30])
    results=[];(out/'controls').mkdir()
    with tempfile.TemporaryDirectory(prefix='fixed-n21-inert-') as name:
        path=Path(name)/'inert.elf'
        for control in controls:
            at=int(control['va'],16);before,after=bytes.fromhex(control['before']),bytes.fromhex(control['after'])
            require(image.read(at,len(before))==before and len(before)==len(after),'frozen mutation anchor/width')
            mutated=bytearray(data);offset=image.offset(at,len(before));mutated[offset:offset+len(before)]=after
            path.write_bytes(mutated);path.chmod(0o600)
            lo,hi=(0x4912a50,0x4912d13) if at<0x4918d30 else (0x4918d30,0x49190b7)
            rows,streams=decode(path,mutated,lo,hi,llvm)
            try:properties(rows)
            except ValueError as error:require(str(error)==control['name'],'wrong static rejection')
            else:raise ValueError('operative operand control accepted')
            item=dict(name=control['name'],va=control['va'],before=control['before'],after=control['after'],actual_operand=rows[at][1],streams={})
            for tool,payloads in zip(['gnu','llvm'],streams):
                item['streams'][tool]={}
                for kind,payload in zip(['stdout','stderr'],payloads):
                    file=out/'controls'/(control['name']+'.'+tool+'.'+kind);file.write_bytes(payload)
                    item['streams'][tool][kind]=dict(bytes=len(payload),sha256=sha(payload))
            results.append(item);path.unlink()
    report=dict(target_sha256=SHA,functions=functions,selected_direct_calls=expected['selected_direct_calls'],controls=results,
                captured_execution=False,instruction_evaluation=False,support_source_sha256=sha(SUPPORT.read_bytes()),
                limits='37finite operand/decoder distinctions, not executed array counterexamples. Exact raw stdout/stderr retained; tempfile filename headers differ between runs. Failure helpers/ABI/unwind and generic counts unclaimed.')
    (out/'native-report.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--binary',type=Path,default=ROOT/'artifacts/node/94/hl-node');p.add_argument('--llvm',type=Path,required=True);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    verify(args.binary,args.llvm,args.out);print('PASS: four complete FDE/body bindings and37finite native operand/caller controls; no captured execution')
