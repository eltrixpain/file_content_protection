from graphviz import Digraph

g = Digraph('FileGuard_Architecture_Simple', format='png')
g.attr(rankdir='TB', bgcolor='white')

internal = {'shape': 'rect', 'style': 'rounded,filled', 'fillcolor': '#1f2937', 'fontcolor': 'white', 'color': '#0ea5e9'}
external = {'shape': 'rect', 'style': 'rounded,filled', 'fillcolor': '#f59e0b', 'fontcolor': 'black', 'color': '#b45309'}
light    = {'shape': 'rect', 'style': 'rounded,filled', 'fillcolor': '#334155', 'fontcolor': 'white', 'color': '#94a3b8'}
proc     = {'shape': 'rect', 'style': 'rounded,filled', 'fillcolor': '#0f766e', 'fontcolor': 'white', 'color': '#14b8a6'}

# External
g.node('fs', 'File System / OS', **external)

# Core
g.node('core', 'CoreEngine\n(fanotify loop + reply)', **internal)

# Collapsed cache layer
g.node('cache', 'Cache Layer\n(L2 in-memory + L1 SQLite + WAL)', **internal)

# Collapsed evaluation
g.node('eval', 'Evaluation Pipeline\n(Rules + Parse + Scan)', **internal)

# Pools (keep your “logic fix”)
g.node('misspool', 'MissWorker Pool\n(normal priority)', **internal)
g.node('bgq', 'Background Queue', **internal)
g.node('bgpool', 'BackgroundWorker Pool\n(low priority)', **internal)

# Warmup + config + logs
g.node('warm', 'Warmup', **light)
g.node('cfg', 'Config / Requirements', **light)
g.node('log', 'Logging / Audit', **proc)

# ---- Main edges (minimal) ----
g.edge('fs', 'core', label='OPEN_PERM', color='#64748b')
g.edge('core', 'fs', label='ALLOW/DENY', color='#64748b')

g.edge('cfg', 'core', label='rules/limits/watch target', color='#94a3b8')

g.edge('core', 'cache', label='lookup', color='#22c55e')
g.edge('cache', 'core', label='hit decision', color='#22c55e')

# Miss -> dedicated pool -> eval
g.edge('core', 'misspool', label='miss', color='#f97316')
g.edge('misspool', 'eval', label='run', color='#f97316')

# Background path (large files + warmup)
g.edge('core', 'bgq', label='large file', color='#f43f5e')
g.edge('warm', 'bgq', label='enqueue', color='#f43f5e')
g.edge('bgq', 'bgpool', label='dispatch', color='#f43f5e')
g.edge('bgpool', 'eval', label='run', color='#f43f5e')

# Eval updates cache (single line)
g.edge('eval', 'cache', label='update decision', color='#22c55e')

# Logging (single sink)
g.edge('core', 'log', label='events', color='#10b981')
g.edge('misspool', 'log', label='decisions', color='#10b981')
g.edge('bgpool', 'log', label='background', color='#10b981')

# Optional: keep eval & warm visually close
with g.subgraph() as s:
    s.attr(rank='same')
    s.node('warm')
    s.node('eval')

png_path = g.render(filename='fileguard_architecture_simple')
print(png_path)
