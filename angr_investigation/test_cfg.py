#!/usr/bin/env python3
"""Test CFG analysis on Silicon Labs firmware with patched CLE"""

import angr
import sys

binary = '/connectedhomeip/out/smoke/thread/BRD2601B/matter-silabs-smoke-co-alarm-example.out'

try:
    print('Loading binary...')
    p = angr.Project(binary, auto_load_libs=False)
    print(f'Architecture: {p.arch.name}')

    print('Running CFG analysis...')
    cfg = p.analyses.CFGFast()

    print(f'✅ SUCCESS! Found {len(cfg.kb.functions)} functions')
    print(f'✅ CFG nodes: {len(cfg.graph.nodes())}')
    print(f'✅ Call graph edges: {len(cfg.kb.callgraph.edges())}')

except Exception as e:
    print(f'❌ FAILED: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
