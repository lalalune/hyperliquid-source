"""Deliberately wrong copies of our Rust, never captured instructions."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess
import argparse
p=argparse.ArgumentParser();p.add_argument("--cargo",required=True);p.add_argument("--output",required=True,type=Path);a=p.parse_args()
W=Path(__file__).resolve().parents[3];C=W/"src/node115-link-staking-state";E=Path(__file__).resolve().parent;O=a.output
assert not O.resolve().is_relative_to(W.resolve()),"Use a fresh output directory outside the source tree"
O.mkdir(parents=True,exist_ok=False)
source=(C/"src/lib.rs").read_text(encoding="utf-8");original=hashlib.sha256((C/"src/lib.rs").read_bytes()).hexdigest()
assert original=="d70cf5e06cce123c5a8a67821617cf25804b1b09c8852f4af98294579a3f0fcc"
start="Mode::Finalize => {\n            let pending"
bad_stake='Mode::Finalize => {\n            if !stake_keys.contains(&staking) { return Outcome { result: Err(LinkError::MissingStakeKey), writes: Vec::new() }; }\n            let pending'
bad_self='Mode::Finalize => {\n            if staking == trading { return Outcome { result: Err(LinkError::SameKeys), writes: Vec::new() }; }\n            let pending'
first='if !stake_keys.contains(&staking) {\n                Some(LinkError::MissingStakeKey)\n            } else if staking == trading {\n                Some(LinkError::SameKeys)\n'
self_first='if staking == trading {\n                Some(LinkError::SameKeys)\n            } else if !stake_keys.contains(&staking) {\n                Some(LinkError::MissingStakeKey)\n'
trade_first='} else if linked(relations.get(&trading)) {\n                Some(LinkError::TradingAlreadyLinked)\n            } else if linked(relations.get(&staking)) {\n                Some(LinkError::StakingAlreadyLinked)\n'
stake_first='} else if linked(relations.get(&staking)) {\n                Some(LinkError::StakingAlreadyLinked)\n            } else if linked(relations.get(&trading)) {\n                Some(LinkError::TradingAlreadyLinked)\n'
changes={
 "invented-finalize-stake-gate":(start,bad_stake),
 "invented-finalize-self-gate":(start,bad_self),
 "self-before-stake-precedence":(first,self_first),
 "reverse-actual-upserts":("for write in &writes {","for write in writes.iter().rev() {"),
 "ignore-pending-peer":("row.kind == RelationKind::Pending && row.peer == staking","row.kind == RelationKind::Pending"),
 "wrong-relationship-precedence":(trade_first,stake_first),
 "refuse-pending-replacement":("else if linked(relations.get(&trading)) {","else if relations.contains_key(&trading) {"),
 "swap-forwarded-key-roles":("Mode::Request => (payload_key, caller_key)","Mode::Request => (caller_key, payload_key)"),
 "wrong-native-error-text":('"Trading user already has a link established"','"Staking user already has a link established"'),
}
cargo=Path(a.cargo);records=[]
for name,(old,new) in changes.items():
 assert source.count(old)==1,(name,source.count(old))
 dest=O/"rust-counterfactuals"/name;assert not dest.exists()
 crate=dest/"src/node115-link-staking-state";shutil.copytree(C,crate)
 fixtures=dest/"research/work-items/RE-010-link-staking-state-115";fixtures.mkdir(parents=True)
 for f in ["frozen-cases.tsv","messages.tsv"]:(fixtures/f).write_bytes((E/f).read_bytes())
 (crate/"src/lib.rs").write_text(source.replace(old,new),encoding="utf-8",newline="\n")
 command=[str(cargo),"test","--offline","--locked","--manifest-path",str(crate/"Cargo.toml"),"--test","frozen_state","--target-dir",str(O/"counterfactual-target"/name)]
 print("$ own Rust wrong transition "+name,flush=True);p=subprocess.run(command,cwd=dest,env=os.environ,capture_output=True,timeout=300)
 (O/("counterfactual-"+name+".stdout")).write_bytes(p.stdout);(O/("counterfactual-"+name+".stderr")).write_bytes(p.stderr)
 detected=p.returncode==101 and b"frozen_whole_state_transitions ... FAILED" in p.stdout
 records.append({"name":name,"exitCode":p.returncode,"compiledAndWholeStateComparisonFailed":detected,"sourceSha256":hashlib.sha256((crate/"src/lib.rs").read_bytes()).hexdigest(),"stdoutSha256":hashlib.sha256(p.stdout).hexdigest(),"stderrSha256":hashlib.sha256(p.stderr).hexdigest()})
 (O/"rust-counterfactuals.json").write_text(json.dumps({"records":records,"targetExecuted":False,"targetEmulated":False},indent=2)+"\n",encoding="utf-8",newline="\n")
 print((p.stdout+p.stderr).decode(errors="replace")[-1500:],flush=True)
 assert detected,name
assert hashlib.sha256((C/"src/lib.rs").read_bytes()).hexdigest()==original
result={"records":records,"allNineCounterfactualsDetected":True,"productionSourceUnchanged":True,"targetExecuted":False,"targetEmulated":False,"nativeRuntimeEquivalenceClaimed":False}
(O/"rust-counterfactuals.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8",newline="\n")
print(json.dumps({"counterfactuals":9,"eachCompiledAndFailedExpectedComparison":True,"productionSourceUnchanged":True}),flush=True)
