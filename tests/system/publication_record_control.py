#!/usr/bin/env python3
"""Test recorded-evidence rejection with virtual edits; original ZIP stays intact."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
from verify_publication_evidence import Records, verify_records


class ChangedRecords(Records):
    def __init__(self, path, mutation):
        super().__init__(path)
        self.mutation = mutation

    def read(self, name):
        value = super().read(name)
        if self.mutation == 'authorized-row' and name.startswith('publication-decision-') and name.endswith('/no-signal/stdout.bin'):
            value = value.replace(b'"rows":[[7]]',b'"rows":[[99]]')
        return value

    def value(self, name):
        value = super().value(name)
        if self.mutation == 'signal-identity' and name.startswith('publication-decision-') and name.endswith('/before-commit-sigterm/debugger-observation.json'):
            value['signal_method'] = 'GDB signal SIGINT to the owned stopped inferior'
        if self.mutation == 'source-lineage' and name.startswith('publication-control-'):
            prefix = name.split('/')[0]
            wrong = super().value(prefix+'/commands/mutant/receipt.json')['source_before']
            if name == prefix+'/commands/baseline/receipt.json':
                value['source_before'] = wrong
                value['source_after_sha256'] = wrong['sha256']
            if name == prefix+'/summary.json':
                for command in value['commands']:
                    if command['label'] == 'baseline': command['source_sha256'] = wrong['sha256']
        return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--zip',type=Path,required=True)
    parser.add_argument('--source-checkout',type=Path,required=True)
    parser.add_argument('--commit',required=True)
    args = parser.parse_args()
    original = hashlib.sha256(args.zip.read_bytes()).hexdigest()
    expected_errors = {'signal-identity':'actual signal identity differs',
                       'source-lineage':'control command expected source lineage differs',
                       'authorized-row':'success differs from independent authorized expectation'}
    controls = []
    for mutation, expected in expected_errors.items():
        sequence, reasons = [], []
        for selected in (None,mutation,None):
            records = ChangedRecords(args.zip,selected)
            try:
                outcome = verify_records(records,args.source_checkout.resolve(),args.commit)
                sequence.append(outcome['status']); reasons.append(None)
            except ValueError as error:
                sequence.append('FAIL'); reasons.append(str(error))
            finally:
                records.archive.close()
        controls.append({'mutation':mutation,'sequence':sequence,'failure_reason':reasons[1],
                         'status':'PASS' if sequence == ['PASS','FAIL','PASS'] and reasons[1] == expected else 'FAIL'})
    unchanged = hashlib.sha256(args.zip.read_bytes()).hexdigest() == original
    result = {'status':'PASS' if unchanged and all(row['status'] == 'PASS' for row in controls) else 'FAIL',
              'campaign':'publication-record-corruption-controls','controls':controls,
              'original_files_mutated':not unchanged,'new_query_execution':False,
              'scope':'actual retained artifact validated with virtual decoded-record/raw-response edits; no product, signal or benchmark execution'}
    print(json.dumps(result,indent=2))
    return int(result['status'] != 'PASS')


if __name__ == '__main__':
    raise SystemExit(main())
