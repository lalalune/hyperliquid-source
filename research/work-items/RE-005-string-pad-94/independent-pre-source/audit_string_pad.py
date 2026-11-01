#!/usr/bin/env python3
"""Separate raw-protocol and sequential high-level request audit; no CPU model."""
import hashlib,itertools,json
from pathlib import Path
root=Path(__file__).parent
sha=lambda b:hashlib.sha256(b).hexdigest()
freeze=json.loads((root/'string-pad-1081-FREEZE.json').read_bytes())
assert sha((root/'generate_string_pad.py').read_bytes())==freeze['generator_sha256']
for name,row in freeze['files'].items():
 raw=(root/name).read_bytes();assert len(raw)==row['bytes']and sha(raw)==row['sha256']
authority=json.loads((root/'string-pad-1081-authority.json').read_bytes())
observations=records=0;seen=set();statuses=set()
with (root/'string-pad-1081-input.tsv').open()as inputs,(root/'string-pad-1081-expected.jsonl').open()as expected:
 for case,input_line,answer_line in zip(authority['cases'],inputs,expected,strict=True):
  fields=input_line.rstrip('\n').split('\t');assert len(fields)==8
  identifier,encoded,word,data,table,method_text,script_text,alignment=fields
  text=bytes.fromhex(encoded).decode('utf8');word=int(word,16);data=int(data,16);table=int(table,16);alignment=int(alignment)
  methods={};method_rows=[]
  for row in method_text.split(','):
   key,char,string=map(lambda v:int(v,16),row.split(':'));methods[key]=[char,string];method_rows.append([key,char,string])
  script={};script_rows=[]
  if script_text!='-':
   for entry in script_text.split(';'):
    ordinal,reply,actions=entry.split('~');ordinal=int(ordinal);reply=int(reply);parsed=[]
    if actions!='-':
     for action in actions.split('/'):
      if action[0]=='M':parsed.append(['M',*[int(v,16)for v in action[1:].split(',')]])
      else:parsed.append([action[0],int(action[1:],16)])
    script[ordinal]=(reply,parsed);script_rows.append([ordinal,reply,parsed])
  assert [identifier,text,word,data,table,method_rows,script_rows,alignment]==[case['id'],case['text'],case['tailword'],case['data'],case['table'],case['methods'],case['script'],case['text_alignment']]
  seen.add(tuple(fields[1:]))
  options=word&0x18000000
  chosen=''.join(itertools.islice(iter(text),word>>48))if word&0x10000000 else text
  if not options:chosen=text;shortfall=0
  else:shortfall=max(0,((word>>32)&65535)-sum(1 for _ in chosen))
  alignment_code=(word>>29)&3
  before=shortfall if alignment_code==1 else shortfall//2 if alignment_code==2 else 0
  requests=itertools.chain(itertools.repeat(('char',word&0x1fffff),before),[('str',chosen.encode().hex())],itertools.repeat(('char',word&0x1fffff),shortfall-before))
  cached_data,cached_table=data,table;current_word=word;event_runs=[];count=0;status=0
  for ordinal,(kind,arg)in enumerate(requests):
   reply,actions=script.get(ordinal,(0,[]))
   event=dict(argument=arg,context_data=data,context_table=table,context_tailword=current_word,
              data=cached_data,kind=kind,method=methods[cached_table][kind=='str'],reply=reply,table=cached_table)
   if event_runs and event_runs[-1]['event']==event:event_runs[-1]['count']+=1
   else:event_runs.append({'count':1,'event':event})
   count+=1
   for action in actions:
    if action[0]=='T':current_word=action[1]
    elif action[0]=='D':data=action[1]
    elif action[0]=='B':table=action[1]
    elif action[0]=='M':methods[action[1]]=[action[2],action[3]]
    else:raise AssertionError('unknown supplied action')
   if reply:
    status=int(shortfall>0)or reply
    break
  answer=dict(callback_count=count,events=event_runs,final_data=data,final_methods=[[key,*methods[key]]for key in sorted(methods)],
              final_table=table,final_tailword=current_word,id=identifier,text_alignment=alignment,raw_status=status)
  assert json.dumps(answer,sort_keys=True,separators=(',',':'))+'\n'==answer_line,identifier
  observations+=count;records+=len(event_runs);statuses.add(status)
assert len(seen)==freeze['case_count']==26054
assert observations==freeze['total_callback_observations']==9915008 and records==freeze['exact_RLE_records']==49649
assert statuses==set(range(256))
receipt={'schema':'string-pad-1081-independent-pre-source-protocol-audit-v1','status':'PASS','cases':26054,
 'all_eight_raw_fields_roundtrip_authority':True,'all_expected_canonical_lines_match_sequential_high_level_reference':True,
 'individual_callback_observations':observations,'exact_adjacent_RLE_records':records,'all_raw_status_bytes':256,
 'freeze_sha256':sha((root/'string-pad-1081-FREEZE.json').read_bytes()),'audit_source_sha256':sha(Path(__file__).read_bytes()),
 'native_instruction_evaluator_or_target_or_Rust_execution':False,'scope':'Raw protocol and supplied callback mathematics only; normal-domain native proof is separate.'}
path=root/'string-pad-1081-PROTOCOL-AUDIT.json';path.write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
print(json.dumps(receipt,sort_keys=True))
