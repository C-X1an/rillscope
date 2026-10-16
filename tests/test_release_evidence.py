"""Actual public artifact corruption controls and independent percentile fixtures."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'benchmarks'))
import release_audit
from run import distribution
from evidence_coverage import coverage, wording_hashes
import tempfile


class PublicEvidenceTests(unittest.TestCase):
    def test_wording_review_is_invalidated_by_changed_added_or_deleted_prose(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); path = root / 'README.md'; path.write_text('Experimental unit fixture.\n')
            observation = {'review_kind':'independent-public-wording','review_status':'PASS','unsupported_maturity_claims':[],
                           'inspection_only':True,'reviewed_wording_sha256':wording_hashes(root)}
            data = {'source_files':[],'observations':[observation]}
            self.assertIn('PUBLIC-WORDING',coverage(data,root))
            path.write_text('Production ready; unmeasured latency is guaranteed.\n')
            self.assertNotIn('PUBLIC-WORDING',coverage(data,root))
            path.write_text('Experimental unit fixture.\n'); added = root / 'new-claim.md'; added.write_text('Unit added document.\n')
            self.assertNotIn('PUBLIC-WORDING',coverage(data,root))
            added.unlink(); path.unlink()
            self.assertNotIn('PUBLIC-WORDING',coverage(data,root))

    def test_only_machine_claim_metadata_is_separately_live_validated(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve(); path = root / 'CLAIMS_EVIDENCE.md'
            original = '| C-027: Evidence | NFR-004 | current proof | [old-run](verification/old.json) | NOT RUN |\n'
            path.write_text(original); before = wording_hashes(root)
            path.write_text(original.replace('[old-run](verification/old.json)','[new-run](verification/new.json)').replace('NOT RUN','PASS'))
            self.assertEqual(wording_hashes(root),before)
            path.write_text(original.replace('C-027: Evidence','C-027: Production ready'))
            self.assertNotEqual(wording_hashes(root),before)
            path.write_text(original.replace('[old-run](verification/old.json)','Production ready [old-run](verification/old.json)'))
            self.assertNotEqual(wording_hashes(root),before)

    def test_claim_markdown_destination_must_match_index_artifact(self):
        path = ROOT / 'CLAIMS_EVIDENCE.md'
        original = Path.read_text
        table = path.read_text(encoding='utf-8')
        index = json.loads((ROOT / 'verification/product/index.json').read_bytes())
        actual = index['artifacts'][index['criteria']['AC-001']['runs'][0]]['path']
        changed = table.replace('](' + actual + ')', '](verification/product/nonexistent.json)', 1)
        def read(file, *args, **kwargs): return changed if file == path else original(file, *args, **kwargs)
        with patch.object(Path, 'read_text', read): result = release_audit.audit(index)
        self.assertIn('claim Markdown links/index artifacts differ: AC-001', result['errors'])
        self.assertIn('claim Markdown evidence link is missing/invalid: AC-001', result['errors'])

    def test_license_observation_is_recognized_without_inventing_wording_review(self):
        # Coverage metadata fixture; no license audit or independent review is claimed.
        sources = ['Cargo.lock','scripts/license_audit.py','licenses/dependency-inventory.json','THIRD_PARTY_NOTICES.md']
        observation = {'license_audit_status':'PASS','errors':[], 'first_party_license':'MIT',
                       'registry_packages':26,'preserved_notice_files':27,'lockfile_sha256':'a' * 64}
        data = {'source_files':[[name,'b' * 64] for name in sources], 'observations':[observation]}
        self.assertIn('LICENSE-NOTICES', coverage(data))
        self.assertNotIn('PUBLIC-WORDING', coverage(data))
        data['observations'][0] = dict(observation, errors=['unit missing notice'])
        self.assertNotIn('LICENSE-NOTICES', coverage(data))

    def test_real_public_artifact_digest_pass_fail_pass(self):
        index = json.loads((ROOT / 'verification/product/index.json').read_bytes())
        self.assertEqual(release_audit.audit(index)['audit_status'], 'PASS')
        mutated = copy.deepcopy(index)
        name = next(iter(mutated['artifacts']))
        mutated['artifacts'][name]['sha256'] = '0' * 64
        result = release_audit.audit(mutated)
        self.assertEqual(result['audit_status'], 'FAIL')
        self.assertIn('public evidence digest mismatch: ' + name, result['errors'])
        self.assertEqual(release_audit.audit(index)['audit_status'], 'PASS')

    def test_missing_locked_criterion_cannot_audit_green(self):
        index = json.loads((ROOT / 'verification/product/index.json').read_bytes())
        del index['criteria']['AC-023']
        self.assertEqual(release_audit.audit(index)['audit_status'], 'FAIL')

    def test_thirty_observation_nearest_rank_is_not_a_tail_guarantee(self):
        result = distribution(list(range(1, 31)))
        self.assertEqual((result['n'], result['p50'], result['p95'], result['p99']), (30, 15.5, 29, 30))
        self.assertEqual(distribution([]), {'n': 0, 'status': 'NOT MEASURED'})


if __name__ == '__main__': unittest.main()
