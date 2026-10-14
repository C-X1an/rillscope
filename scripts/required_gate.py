#!/usr/bin/env python3
"""Explicitly fail incomplete required product gates; never silently skip them."""
import json
import sys
name = sys.argv[1] if len(sys.argv) == 2 else 'unknown'
print(json.dumps({'gate': name, 'status': 'INCOMPLETE', 'reason': 'Full Rust implementation and evidence for this gate are not yet present. Implement the gate against locked acceptance criteria; do not replace with a constant success.'}))
raise SystemExit(78)
