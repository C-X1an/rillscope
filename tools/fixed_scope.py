"""Operator-configured local adapter. The client supplies query and output only."""
from __future__ import annotations
import json
import os
from pathlib import Path
import subprocess

QUERY_BYTES = 65536
ENVIRONMENT_KEYS = ('SYSTEMROOT', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP')

def failure(code, phase, message):
    return {'version': 1, 'status': 'error', 'error': {'code': code, 'phase': phase, 'message': message},
            'implementation': 'python-adapter'}

class FixedScopeAdapter:
    """Construction is trusted host activity; this is not a network/auth service."""
    def __init__(self, *, binary: Path, catalog: Path, context: Path):
        self._binary, self._catalog, self._context = (Path(p).resolve() for p in (binary, catalog, context))
        if not all(p.is_file() for p in (self._binary, self._catalog, self._context)):
            raise ValueError('operator configuration is unavailable')

    def call(self, request):
        if not isinstance(request, dict) or set(request) != {'query', 'output'}:
            return failure('E_INPUT', 'input', 'invalid adapter request')
        query = request['query']
        if (not isinstance(query, dict) or set(query) != {'format', 'source'} or
            query['format'] not in ('json', 'sql') or not isinstance(query['source'], str) or
            request['output'] not in ('rows', 'explain')):
            return failure('E_INPUT', 'input', 'invalid adapter request')
        if len(query['source']) > QUERY_BYTES:
            return failure('E_LIMIT', 'input', 'query exceeds input limits')
        try:
            data = query['source'].encode('utf-8')
        except UnicodeEncodeError:
            return failure('E_INPUT', 'input', 'invalid query encoding')
        if len(data) > QUERY_BYTES:
            return failure('E_LIMIT', 'input', 'query exceeds input limits')
        command = [str(self._binary), 'run' if request['output'] == 'rows' else 'explain',
                   '--catalog', str(self._catalog), '--context', str(self._context),
                   '--query', '-', '--format', query['format']]
        # Do not inherit keys, test hooks, PATH, HOME, query-selected paths or shell settings.
        env = {key: os.environ[key] for key in ENVIRONMENT_KEYS if key in os.environ}
        try:
            result = subprocess.run(command, input=data, capture_output=True, env=env, timeout=20)
        except subprocess.TimeoutExpired:
            return failure('E_CANCELLED', 'execute', 'query process deadline exceeded')
        except OSError:
            return failure('E_INTERNAL', 'execute', 'query process unavailable')
        if result.stderr or len(result.stdout) > 1024 * 1024 + 1:
            return failure('E_INTERNAL', 'execute', 'invalid query process response')
        try:
            response = json.loads(result.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return failure('E_INTERNAL', 'execute', 'invalid query process response')
        if not isinstance(response, dict) or response.get('implementation') != 'rust':
            return failure('E_INTERNAL', 'execute', 'invalid query process response')
        if response.get('status') == 'error':
            if result.returncode == 0 or 'rows' in response:
                return failure('E_INTERNAL', 'execute', 'invalid query process response')
        elif result.returncode != 0 or response.get('status') != 'ok':
            return failure('E_INTERNAL', 'execute', 'invalid query process response')
        return response
