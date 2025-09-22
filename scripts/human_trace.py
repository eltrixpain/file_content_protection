#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# human_trace_replay.py
# Usage example:
#   python3 human_trace_replay.py --dir /path/to/your/folder --accesses 3000 --duration 240

import os
import sys
import time
import random
import argparse
import math
from pathlib import Path

# ---------------------------
# Helper functions (English comments only)
# ---------------------------

def list_files_in_dir(d):
    """Return list of regular files in directory d (shallow, not recursive)."""
    p = Path(d)
    files = [str(x) for x in p.iterdir() if x.is_file()]
    files.sort()  # deterministic order
    return files

def choose_local_set(files, local_size):
    """Choose a contiguous-ish local set by index to simulate folder-area locality.
       We choose a random pivot index and take up to local_size neighbors."""
    n = len(files)
    if n == 0:
        return []
    pivot = random.randrange(n)
    half = local_size // 2
    lo = max(0, pivot - half)
    hi = min(n, lo + local_size)
    return files[lo:hi]

def human_delay(burst_mode):
    """Return a delay (seconds). burst_mode True -> short delay (reading several files).
       burst_mode False -> inter-session or occasional pause (longer)."""
    if burst_mode:
        # within a burst: short, human read ~10-120 ms
        return random.uniform(0.01, 0.12)
    else:
        # between bursts/sessions: longer pause, 100-800 ms typical; occasionally longer (2-6s)
        if random.random() < 0.05:
            return random.uniform(2.0, 6.0)
        return random.uniform(0.1, 0.8)

def touch_file_mtime(path):
    """Update file mtime to now without changing content (os.utime)."""
    now = time.time()
    os.utime(path, (now, now))

def append_small(path):
    """Append a small byte to the file (changes size). Less safe but simulates write."""
    try:
        with open(path, "ab") as f:
            f.write(b"\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass

def open_and_close_read(path, iosize=4096, do_read=False):
    """Open file for read and immediately close; optionally perform a small read."""
    try:
        fd = os.open(path, os.O_RDONLY)
        if do_read:
            try:
                os.read(fd, iosize)
            except Exception:
                pass
        os.close(fd)
    except Exception:
        pass

# ---------------------------
# Trace generator + replay
# ---------------------------

def run_simulation(directory, total_accesses=3000, duration=240.0,
                   avg_session_len=20, avg_burst_len=5,
                   local_prob=0.7, write_rate=0.01,
                   write_mode='touch', verbose=True):
    """
    directory       : target directory containing files (flat)
    total_accesses  : number of open/read actions to perform
    duration        : target wall-clock seconds for whole run (used to bias delays)
    avg_session_len : average number of bursts per session (controls sessionization)
    avg_burst_len   : average number of files accessed per burst (spatial locality)
    local_prob      : probability to pick next file from current local set (spatial)
    write_rate      : fraction of accesses that perform a "write" (touch) to invalidate
    write_mode      : 'touch' or 'append'
    """
    files = list_files_in_dir(directory)
    if not files:
        print(f"No files found in {directory}", file=sys.stderr)
        return

    n_files = len(files)
    print(f"Found {n_files} files in {directory}", file=sys.stderr)
    if total_accesses <= 0:
        return

    accesses_done = 0
    start_time = time.time()
    end_time_target = start_time + duration
    seed = int(start_time) ^ os.getpid()
    random.seed(seed)

    # We will create sessions. Each session has several bursts.
    # Keep a current local set and do bursts inside it.
    session_count = 0
    last_report = 0

    # Precompute a small list of "hot" indices to bias selection a bit:
    # Choose ~5% of files as occasional "hot" candidates (simulate popular files)
    hot_count = max(1, n_files // 20)
    hot_indices = random.sample(range(n_files), hot_count)
    hot_set = {files[i] for i in hot_indices}

    # main loop
    local_set = []
    while accesses_done < total_accesses:
        # start a new session
        session_count += 1
        # how many bursts in this session (geometric-like)
        bursts = max(1, int(random.expovariate(1.0 / avg_session_len)))
        # pick a local set for the session (size random 3..avg_burst_len*3)
        local_size = max(3, min(n_files, int(random.gauss(avg_burst_len*2, avg_burst_len))))
        local_set = choose_local_set(files, local_size)

        for b in range(bursts):
            # burst length (#files accessed in this burst)
            burst_len = max(1, int(random.expovariate(1.0 / avg_burst_len)))
            for i in range(burst_len):
                if accesses_done >= total_accesses:
                    break

                # choose between local vs global vs hot
                r = random.random()
                if r < local_prob and local_set:
                    pick = random.choice(local_set)
                elif r < local_prob + 0.1 and hot_set:
                    pick = random.choice(list(hot_set))
                else:
                    pick = random.choice(files)

                # perform access (open + optional small read)
                open_and_close_read(pick, iosize=4096, do_read=True)

                # sometimes perform write/touch to invalidate
                if random.random() < write_rate:
                    if write_mode == 'append':
                        append_small(pick)
                    else:
                        touch_file_mtime(pick)

                accesses_done += 1

                # compute delay
                d = human_delay(burst_mode=True)
                # bias delays slightly to meet overall duration target:
                # compute remaining accesses and remaining time
                remaining = max(1, total_accesses - accesses_done)
                now = time.time()
                rem_time = max(0.001, end_time_target - now)
                avg_needed = rem_time / remaining
                # blend human delay and avg_needed to stretch/shrink to target duration
                alpha = 0.35
                d = (1.0 - alpha) * d + alpha * avg_needed
                time.sleep(d)

                # periodic report
                if verbose and (accesses_done % 100 == 0 and accesses_done != last_report):
                    last_report = accesses_done
                    elapsed = time.time() - start_time
                    print(f"[progress] accesses={accesses_done}/{total_accesses} elapsed={elapsed:.1f}s", file=sys.stderr)

            # small pause between bursts
            if accesses_done >= total_accesses:
                break
            time.sleep(human_delay(burst_mode=False))

        # after session, longer idle (simulate user thinking)
        if accesses_done < total_accesses:
            time.sleep(random.uniform(0.2, 1.5))

    total_elapsed = time.time() - start_time
    print(f"[done] accesses={accesses_done} time={total_elapsed:.1f}s sessions={session_count}", file=sys.stderr)


# ---------------------------
# CLI
# ---------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Human-like trace replayer for a single dir")
    p.add_argument("--dir", "-d", required=True, help="Directory containing target files (flat)")
    p.add_argument("--accesses", type=int, default=3000, help="Total number of accesses (default 3000)")
    p.add_argument("--duration", type=float, default=240.0, help="Approx target duration seconds (default 240s)")
    p.add_argument("--avg-session", type=float, default=20.0, help="Average session length (bursts) (default 20)")
    p.add_argument("--avg-burst", type=float, default=5.0, help="Average burst length (files per burst) (default 5)")
    p.add_argument("--local-prob", type=float, default=0.7, help="Probability to pick from local set (default 0.7)")
    p.add_argument("--write-rate", type=float, default=0.01, help="Fraction of accesses that touch file to invalidate (default 0.01)")
    p.add_argument("--write-mode", choices=["touch", "append"], default="touch", help="How to invalidate (touch vs append)")
    p.add_argument("--quiet", action="store_true", help="Quiet mode")
    return p.parse_args()

def main():
    args = parse_args()
    if not os.path.isdir(args.dir):
        print("Error: directory does not exist", file=sys.stderr)
        sys.exit(1)

    run_simulation(args.dir, total_accesses=args.accesses, duration=args.duration,
                   avg_session_len=args.avg_session, avg_burst_len=args.avg_burst,
                   local_prob=args.local_prob, write_rate=args.write_rate,
                   write_mode=args.write_mode, verbose=not args.quiet)

if __name__ == "__main__":
    main()
