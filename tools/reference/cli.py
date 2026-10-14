"""Run the JSON-only reference against operator-selected files."""
import argparse
import json
from pathlib import Path
from .engine import QueryError, evaluate, strict_loads


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--context', type=Path, required=True)
    parser.add_argument('--query', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = evaluate(strict_loads(args.catalog.read_text(), 256 * 1024 * 1024),
                          strict_loads(args.context.read_text()), strict_loads(args.query.read_text()))
    except (OSError, UnicodeError, QueryError) as error:
        result = {'version': 1, 'status': 'error', 'implementation': 'python-reference',
                  'error': {'code': getattr(error, 'code', 'E_INPUT'), 'phase': 'decode',
                            'message': 'reference input could not be loaded'}}
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result['status'] == 'ok' else 2


if __name__ == '__main__':
    raise SystemExit(main())
