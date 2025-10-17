#!/bin/bash
# ---------------------------------------------
# Live monitor for the fileguard process (with threads, mem, io, fds)
# Requires: sudo privileges for full /proc access
# ---------------------------------------------

# Find main PID of fileguard
pid=$(pidof -s fileguard)

if [ -z "$pid" ]; then
  echo "❌ fileguard process not found!"
  exit 1
fi

echo "✅ Monitoring fileguard (PID=$pid)"
echo "Press Ctrl+C to stop."
sleep 1

sudo watch -n 1 "
echo '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
echo '🧠 CPU / THREADS';
sudo ps -L -p $pid -o pid,tid,psr,pri,ni,stat,pcpu,comm --sort=-pcpu | head -n 15;
echo;
echo '💾 MEMORY STATUS';
sudo grep -E 'Threads|VmRSS|VmSize|VmData|VmSwap' /proc/$pid/status;
echo;
echo '📀 I/O COUNTERS';
sudo cat /proc/$pid/io 2>/dev/null;
echo;
echo '📂 OPEN FILE DESCRIPTORS';
sudo ls /proc/$pid/fd 2>/dev/null | wc -l;
echo '━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━';
"

