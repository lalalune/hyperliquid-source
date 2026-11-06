"""Literal JSON-to-Rust test transcription only; no source execution or oracle.

Reads the exact seven-member design freeze. Writes four files to a fresh output
directory. Never imports repository/candidate code or invokes a subprocess.
"""
import argparse
import hashlib
import json
from pathlib import Path

DESIGN_SHA = '62d74a758d9cd8ade061c7dbb04b03bc8b455c213ece5158ebea68a4f17e9c6c'
CASES_SHA = 'bdb707c166c4ab08eb7477528daf10021492d723308cc43458a10be9e1dce164'
def require(ok, message):
    if not ok:
        raise ValueError(message)
def sha(data):
    return hashlib.sha256(data).hexdigest()
def octets(value):
    if isinstance(value, str):
        return value.encode('ascii')
    require(isinstance(value, dict) and set(value)=={'hex'}, 'byte literal shape')
    require(value['hex']==value['hex'].lower(), 'lower hex')
    return bytes.fromhex(value['hex'])
def bs(data):
    return '&[' + ', '.join('0x%02xu8'%b for b in data) + ']'
def name(value):
    require(isinstance(value, dict) and len(value)==1, 'name shape')
    if 'builtin' in value:
        require(type(value['builtin']) is int and 0<=value['builtin']<=255, 'u8 builtin')
        return 'Name::Builtin(%d)'%value['builtin']
    if 'custom' in value:
        return 'Name::Custom(%s)'%bs(octets(value['custom']))
    require('custom_hex' in value, 'custom name')
    return 'Name::Custom(%s)'%bs(octets({'hex':value['custom_hex']}))
def group(value):
    require(isinstance(value,list) and len(value)==2, 'group shape')
    return 'Group { name: %s, values: &[%s] }'%(name(value[0]),', '.join(bs(octets(v))+' as &[u8]' for v in value[1]))
def group_slice(groups):
    return '&[' + ', '.join(group(g) for g in groups) + ']'
def error(e):
    kind=e['kind']
    require(kind in ('UsedBounds','GroupCount','InvalidOrdinal','EmptyValues','DuplicateName','Representation','LengthOverflow','Capacity'), 'error kind')
    if kind in ('UsedBounds','LengthOverflow'):
        require(set(e)=={'kind'}, 'unit error');return 'Error::'+kind
    if kind in ('GroupCount','Representation'):
        require(set(e)=={'kind','map'},'map error');require(e['map'] in ('Primary','Spelling'),'map')
        return 'Error::%s(Map::%s)'%(kind,e['map'])
    if kind=='Capacity':
        require(set(e)=={'kind','required'} and type(e['required']) is int and e['required']>=0,'capacity error')
        return 'Error::Capacity { required: %d }'%e['required']
    require(set(e)=={'kind','map','index'} and e['map'] in ('Primary','Spelling') and type(e['index']) is int and e['index']>=0,'indexed error')
    return 'Error::%s { map: Map::%s, index: %d }'%(kind,e['map'],e['index'])

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--design',required=True,type=Path)
    parser.add_argument('--out',required=True,type=Path)
    args=parser.parse_args()
    require(not args.out.exists(),'fresh output required')
    frozen=(args.design/'FREEZE.json').read_bytes();require(sha(frozen)==DESIGN_SHA,'design freeze')
    manifest=json.loads(frozen)
    allowed={'BUILTIN-NAMES.json','HAND-CHECKS.md','HOST-CONTRACT.md','MANUAL-CASES.json','OVERFLOW-OBLIGATIONS.md','RETURN.json','STRUCTURAL-CHAIN.md'}
    require({x['path'] for x in manifest['files']}==allowed and len(manifest['files'])==7,'exact design paths')
    for entry in manifest['files']:
        path=args.design/entry['path'];require(not path.is_symlink(),'no input symlink')
        raw=path.read_bytes();require(len(raw)==entry['bytes'] and sha(raw)==entry['sha256'],'design member '+entry['path'])
    raw=(args.design/'MANUAL-CASES.json').read_bytes();require(sha(raw)==CASES_SHA,'case source')
    obj=json.loads(raw);cases=obj['cases'];plans=obj['count_boundary_plans']
    require(len(cases)==42 and len(plans)==4,'case counts')
    output=['// Exact literal projection of frozen MANUAL-CASES.json; no output oracle.',
            'use node115_http_header_writer::{append, Error, Group, Map, Name};','']
    probe=['// Input literals only; expected results remain in parent expected.tsv.',
           'use node115_http_header_writer::{append, Error, Group, Map, Name};',
           'fn emit(id: &str, got: Result<usize, Error>, output: &[u8]) {',
           '    let hex: String = output.iter().map(|b| format!("{:02x}", b)).collect();',
           '    match got {',
           '        Ok(n) => println!("{}\\tO\\t{}\\t{}", id, n, hex),',
           '        Err(e) => {',
           '            let (code, map, index, required) = match e {',
           '                Error::UsedBounds => ("UsedBounds", None, None, None),',
           '                Error::GroupCount(m) => ("GroupCount", Some(m), None, None),',
           '                Error::InvalidOrdinal { map, index } => ("InvalidOrdinal", Some(map), Some(index), None),',
           '                Error::EmptyValues { map, index } => ("EmptyValues", Some(map), Some(index), None),',
           '                Error::DuplicateName { map, index } => ("DuplicateName", Some(map), Some(index), None),',
           '                Error::Representation(m) => ("Representation", Some(m), None, None),',
           '                Error::LengthOverflow => ("LengthOverflow", None, None, None),',
           '                Error::Capacity { required } => ("Capacity", None, None, Some(required)),',
           '            };',
           '            let map = match map { None => "-", Some(Map::Primary) => "P", Some(Map::Spelling) => "S" };',
           '            let index = index.map(|n| n.to_string()).unwrap_or_else(|| "-".into());',
           '            let required = required.map(|n| n.to_string()).unwrap_or_else(|| "-".into());',
           '            println!("{}\\tE\\t{}\\t{}\\t{}\\t{}\\t{}", id, code, map, index, required, hex);',
           '        }',
           '    }',
           '}', '']
    expected_rows=[]
    mapping=[];seen=set()
    for c in cases+plans:
        cid=c['id'];require(cid.isascii() and cid.isalnum() and cid not in seen,'unique inert case ID');seen.add(cid)
        body=['#[test]', 'fn case_%s() {'%cid.lower()]
        for key in ('primary','spelling'):
            repeat=c.get(key+'_repeat')
            if repeat:
                require(type(repeat['count']) is int and 0<=repeat['count']<=65536,'repeat bound')
                body.append('    let %s_repeat = vec![%s; %d];'%(key,group(repeat['group']),repeat['count']))
                body.append('    let %s: &[Group<\'_>] = &%s_repeat;'%(key,key))
            else:
                body.append('    let %s: &[Group<\'_>] = %s;'%(key,group_slice(c.get(key,[]))))
        prefix=octets(c.get('prefix',''));capacity=c.get('capacity',64);fill=c.get('fill_byte',165)
        require(type(capacity) is int and 0<=capacity<=4096 and type(fill) is int and 0<=fill<=255,'small buffer policy')
        if 'buffer' in c:
            initial=octets(c['buffer']);require(len(initial)==capacity,'explicit buffer capacity')
        else:
            require(len(prefix)<=capacity,'prefix capacity');initial=prefix+bytes([fill])*(capacity-len(prefix))
        used=c.get('used',len(prefix));require(type(used) is int and 0<=used<=4096,'used')
        cap=c.get('capitalize',False);require(type(cap) is bool,'capitalization bool')
        body.extend(['    let before = (%s).to_vec();'%bs(initial),
                     '    let mut output = before.clone();',
                     '    let got = append(primary, spelling, %s, &mut output, %d);'%('true' if cap else 'false',used)])
        probe.extend(['fn input_%s() {'%cid.lower()]+body[2:]+['    emit("%s", got, &output);'%cid,'}',''])
        if 'error' in c:
            body.extend(['    assert_eq!(got, Err(%s));'%error(c['error']),
                         '    assert_eq!(output, before, "entire buffer changed on refusal");'])
            e=c['error'];expected_rows.append('\t'.join([cid,'E',e['kind'],{'Primary':'P','Spelling':'S'}.get(e.get('map'),'-'),str(e.get('index','-')),str(e.get('required','-')),initial.hex()]))
        else:
            expected=octets({'hex':c['expected_hex']}) if 'expected_hex' in c else octets(c['expected'])
            require(len(expected)==c['used_result']<=capacity and used<=len(expected),'literal length')
            body.extend(['    assert_eq!(got, Ok(%d));'%c['used_result'],
                         '    assert_eq!(&output[..%d], %s);'%(c['used_result'],bs(expected)),
                         '    assert_eq!(&output[..%d], &before[..%d]);'%(used,used),
                         '    assert_eq!(&output[%d..], &before[%d..]);'%(c['used_result'],c['used_result'])])
            expected_rows.append('\t'.join([cid,'O',str(c['used_result']),(expected+initial[c['used_result']:]).hex()]))
        body.extend(['}','']);output.extend(body)
        mapping.append({'id':cid,'rust_test':'case_'+cid.lower(),'literal_case_sha256':sha(json.dumps(c,sort_keys=True,separators=(',',':')).encode()),'kind':'count-plan' if c in plans else 'small-literal'})
    source=('\n'.join(output)+'\n').encode()
    probe.extend(['fn main() {','    if std::env::args_os().len() != 1 { std::process::exit(2); }']+['    input_%s();'%c['id'].lower() for c in cases+plans]+['}',''])
    probe_raw=('\n'.join(probe)+'\n').encode(); expected_raw=('\n'.join(expected_rows)+'\n').encode()
    receipt={'schema':1,'design_freeze_sha256':DESIGN_SHA,'manual_cases_sha256':CASES_SHA,'transcriber_sha256':sha(Path(__file__).read_bytes()),'generated_test_sha256':sha(source),'input_probe_sha256':sha(probe_raw),'parent_expected_sha256':sha(expected_raw),'test_count':len(mapping),'mapping':mapping,'effects':'Representation projection only: numeric/byte Rust literals and literal result assertions. No expected result computed from primary/spelling input. Input-only probe contains no expected fields; parent TSV projects literal expected result plus frozen unchanged buffer suffix. Repeated arrays materialize only when authored Rust later runs.'}
    args.out.mkdir(parents=True,exist_ok=False)
    (args.out/'frozen_cases.rs').write_bytes(source)
    (args.out/'input_probe.rs').write_bytes(probe_raw)
    (args.out/'expected.tsv').write_bytes(expected_raw)
    (args.out/'TRANSCRIPTION.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'generated_test_sha256':sha(source),'test_count':len(mapping)},sort_keys=True))

if __name__=='__main__':
    main()
