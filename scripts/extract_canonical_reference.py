"""Restore bounded original canonical bytes; qualification is a separate gate."""
import argparse
import json
from pathlib import Path
from canonical_reference_bundle import extract


def main(argv=None):
    parser = argparse.ArgumentParser(); parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True); parser.add_argument('--max-bytes', type=int, required=True)
    parser.add_argument('--budget-seconds', type=int, required=True); parser.add_argument('--prefix', action='append', default=[])
    args = parser.parse_args(argv)
    try:
        result = extract(args.archive, args.out, max_bytes=args.max_bytes, budget_seconds=args.budget_seconds, prefixes=args.prefix)
        print(json.dumps(result, sort_keys=True)); return 0
    except (Exception, KeyboardInterrupt) as error:
        print(json.dumps({'status': 'FAIL', 'error': type(error).__name__, 'reason': str(error)[:2048]})); return 1


if __name__ == '__main__': raise SystemExit(main())
