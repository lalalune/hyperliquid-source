import copy, json, pathlib, subprocess, sys, tempfile
ROOT=pathlib.Path.cwd()
sys.path.insert(0,str(ROOT/'tools'))
import catalogue
source=subprocess.check_output(['git','show','1f8c67c63ca4794c9689235471c60297f8a5c985:tools/catalogue.py'],text=True)
base={'__file__':str(ROOT/'tools/catalogue.py'),'__name__':'baseline_catalogue'}
exec(compile(source,'tools/catalogue.py','exec'),base)
progress=json.loads((ROOT/'research/progress.json').read_text())
parts=json.loads((ROOT/'research/components.json').read_text())['components']
results={}
for name in ('additional','missing','replaced'):
    p=copy.deepcopy(progress)
    if name=='additional':
        p['gates']['extra']='Unreviewed additional milestone'
        for row in p['components'].values(): row['gates']['extra']=False
    else:
        del p['gates']['identity']
        for row in p['components'].values(): del row['gates']['identity']
        if name=='replaced':
            p['gates']['source_imported']='Not a reconstruction acceptance gate'
            for row in p['components'].values(): row['gates']['source_imported']=False
    outcomes={}
    for label,validator in [('before',base['validate_progress']),('after',catalogue.validate_progress)]:
        try: validator(parts,p,ROOT); outcomes[label]='accepted'
        except ValueError as exc: outcomes[label]='rejected: '+str(exc)
    results[name]=outcomes
with tempfile.TemporaryDirectory(dir=ROOT/'work') as directory:
    temp=pathlib.Path(directory)
    for rel in ['research/components.json','research/imported/hl-node-94.inventory.json','research/imported/hl-node-115.inventory.json','research/imported/hl-visor.inventory.json','research/imported/can1357-literal-classes.json','CONTRIBUTING.md']:
        dst=temp/rel; dst.parent.mkdir(parents=True,exist_ok=True); dst.write_bytes((ROOT/rel).read_bytes())
    (temp/'references').mkdir(); (temp/'references/can1357-hl').symlink_to((ROOT/'references/can1357-hl').resolve(),target_is_directory=True)
    (temp/'artifacts/node/94').mkdir(parents=True)
    (temp/'artifacts/node/94/hl-node').symlink_to(ROOT/'artifacts/node/94/hl-node')
    p=copy.deepcopy(progress);p['gates']['extra']='Unreviewed additional milestone'
    for row in p['components'].values():row['gates']['extra']=False
    p['components']['foundation']['gates']={k:True for k in p['gates']}
    p['components']['foundation']['evidence']=['CONTRIBUTING.md']
    (temp/'research/progress.json').write_text(json.dumps(p))
    output=base['generate'](temp)['docs/PROGRESS.md']
    results['before_rendered_row']=next(line for line in output.splitlines() if line.startswith('| [Foundation'))
    try:catalogue.generate(temp);results['after_render']='accepted'
    except ValueError as exc:results['after_render']='rejected: '+str(exc)
print(json.dumps(results,indent=2))
