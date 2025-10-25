# Create a more vertical (top-down) diagram and fix logic:
# - Miss path goes directly to RuleEvaluator via a dedicated "MissWorker Pool"
# - Large files and Warmup go to a separate low-priority "BackgroundWorker Pool"
from graphviz import Digraph

g = Digraph('FileGuard_Architecture_v3', format='png')
g.attr(rankdir='TB', bgcolor='white')  # Top-Down (more vertical)

internal = {'shape': 'rect', 'style': 'rounded,filled', 'fillcolor': '#1f2937', 'fontcolor': 'white', 'color': '#0ea5e9'}
external = {'shape': 'rect', 'style': 'rounded,filled', 'fillcolor': '#f59e0b', 'fontcolor': 'black', 'color': '#b45309'}
storage  = {'shape': 'cylinder', 'style': 'filled', 'fillcolor': '#4338ca', 'fontcolor': 'white', 'color': '#a78bfa'}
proc     = {'shape': 'rect', 'style': 'rounded,filled', 'fillcolor': '#0f766e', 'fontcolor': 'white', 'color': '#14b8a6'}
light    = {'shape': 'rect', 'style': 'rounded,filled', 'fillcolor': '#334155', 'fontcolor': 'white', 'color': '#94a3b8'}

# Top row: external
g.node('fs', 'File System / OS', **external)

# Core
g.node('core', 'CoreEngine\n(fanotify loop + reply)', **internal)

# Caches
g.node('l2', 'CacheL2 (in-memory)', **internal)
g.node('l1', 'CacheL1 (SQLite)', **internal)
g.node('db', 'cache.sqlite (WAL)', **storage)

# Parallel processing units
g.node('misspool', 'MissWorker Pool\n(normal priority)\n(concurrency via SimpleSemaphore)', **internal)
g.node('bgq', 'Background Queue', **internal)
g.node('bgpool', 'BackgroundWorker Pool\n(low CPU/IO priority)', **internal)

# Evaluation pipeline (kept central)
g.node('re', 'RuleEvaluator', **internal)
g.node('cp', 'ContentParser', **internal)
g.node('hs', 'PatternMatcherHS\n(Hyperscan)', **internal)

# Warmup & config/logging
g.node('warm', 'Warmup::scope_warmup_on_access', **light)
g.node('cfg', 'ConfigManager\n(ruleset_version, limits)', **light)
g.node('req', 'Requirements\n(folders, db, access)', **light)
g.node('logger', 'Logger (separate process)\npipe → logs/fileguard.log\npipe → logs/config.log', **proc)
g.node('audit', 'System Response / Audit Log', **external)

# Statistic/Simulation (bottom side-plane)
g.node('stat', 'Statistic Mode\n(FAN_OPEN on /home)', **light)
g.node('storeio', 'StatisticStoreIO\nsave/load trace*.bin', **light)
g.node('sim', 'Simulation Mode\nEMA on size95/k95', **light)

# Edges: top to core
g.edge('fs', 'core', label='fanotify OPEN_PERM', color='#64748b')
g.edge('core', 'fs', label='ALLOW/DENY', color='#64748b')

# Config and logging
g.edge('req', 'cfg', label='initialization', color='#94a3b8')
g.edge('cfg', 'core', label='watch_target / ruleset_version', color='#94a3b8')
g.edge('core', 'logger', label='pipe: events', color='#10b981')
g.edge('misspool', 'logger', label='pipe: decisions/blocks', color='#10b981')
g.edge('bgpool', 'logger', label='pipe: background logs', color='#10b981')
g.edge('logger', 'audit', label='append', color='#10b981')

# Cache fast path
g.edge('core', 'l2', label='get()', color='#22c55e')
g.edge('l2', 'core', label='decision', color='#22c55e')
g.edge('l2', 'l1', label='miss → L1.get()', color='#22c55e')
g.edge('l2', 'l2', label='', color="#c522b8")
g.edge('l1', 'l2', label='hit → promote', color='#22c55e')
g.edge('l1', 'db', label='SQL', color='#a78bfa')
g.edge('db', 'l1', label='WAL', color='#a78bfa')

# Miss path -> dedicated pool -> evaluator
g.edge('core', 'misspool', label='cache miss', color='#f97316')
g.edge('misspool', 're', label='schedule task', color='#f97316')

# Large files (threshold) and Warmup -> background queue/pool
g.edge('core', 'bgq', label='size > threshold', color='#f43f5e')
g.edge('warm', 'bgq', label='enqueue neighbors', color='#f43f5e')
g.edge('bgq', 'bgpool', label='pop', color='#f43f5e')

# Parallel hint: Warmup and RuleEvaluator same rank
with g.subgraph() as s:
    s.attr(rank='same')
    s.node('warm')
    s.node('re')

# Evaluation pipeline
g.edge('re', 'cp', label='detect/extract', color='#f43f5e')
g.edge('cp', 're', label='text', color='#f43f5e')
g.edge('re', 'hs', label='scan()', color='#f43f5e')
g.edge('hs', 're', label='match?', color='#f43f5e')

# Cache updates from both pools
g.edge('re', 'l1', label='put(decision)', color='#22c55e')
g.edge('re', 'l2', label='put(copy)', color='#22c55e')
g.edge('bgpool', 're', label='evaluate', color='#f43f5e')

# Stats & sim plane
g.edge('stat', 'storeio', label='save trace.bin', color='#eab308')
g.edge('storeio', 'sim', label='load trace', color='#eab308')

png_path = g.render(filename='fileguard_architecture_v3')

