"""Generate a real catalogue view from pinned metadata and one reference file."""
import hashlib,json,shutil,subprocess,sys,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
import catalogue

class CataloguePortablePaths(unittest.TestCase):
    def test_native_reference_paths_use_the_catalogue_posix_coordinate_system(self):
        reference=ROOT/'references/can1357-hl'
        # Read exact pinned Git bytes even when Windows cannot check out aux.rs.
        source=subprocess.check_output(['git','-C',str(reference),'show','999556f6e0a474b8312db96ec3149e1c44e97c23:base/duration.rs'])
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary)
            for name in ('research/components.json','research/progress.json',
                         'research/imported/hl-node-94.inventory.json',
                         'research/imported/hl-node-115.inventory.json',
                         'research/imported/hl-visor.inventory.json',
                         'research/imported/can1357-literal-classes.json',
                         'artifacts/node/94/hl-node'):
                target=stage/name;target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(ROOT/name,target)
            path=stage/'references/can1357-hl/base/duration.rs'
            path.parent.mkdir(parents=True);path.write_bytes(source)
            try:result=catalogue.generate(stage)
            except ValueError as error:self.fail('native checkout paths must remain classifiable: '+str(error))
            document=json.loads(result['research/catalogue/components.json'])
            foundation=next(row for row in document['components'] if row['id']=='foundation')
            self.assertEqual(foundation['reference_paths'],['base/duration.rs'])
            self.assertEqual(document['path_totals']['reference'],1)
            self.assertEqual(document['path_totals']['reference_first_party'],1)
            self.assertEqual(path.read_bytes(),source)
            seeds=json.loads(result['research/catalogue/seed-candidates.json'])
            self.assertEqual(seeds['binary_sha256'],'3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f')
            self.assertTrue(all('\\' not in row['file'] for row in seeds['items']))

if __name__=='__main__':unittest.main()
