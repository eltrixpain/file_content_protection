#!/usr/bin/env python3
import os
import time
import sys

if len(sys.argv) < 2:
    print(f"Usage: {sys.argv[0]} <folder> [sleep_seconds]")
    sys.exit(1)

root = sys.argv[1]
sleep_time = float(sys.argv[2]) if len(sys.argv) > 2 else 1.0

# walk the directory and collect file paths
files = []
for dirpath, _, filenames in os.walk(root):
    for name in filenames:
        files.append(os.path.join(dirpath, name))

print(f"[info] Found {len(files)} files under {root}")

while True:
    for path in files:
        try:
            with open(path, "rb") as f:
                f.read(64)  # read first 64 bytes
            print(f"[open] {path}")
        except Exception as e:
            print(f"[error] {path}: {e}")
        time.sleep(sleep_time)

