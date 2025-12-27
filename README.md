# file_content_protection  

A small tool for protecting file contents on UNIX-based systems.  
It watches file accesses (using fanotify) and checks them against rules (like regex patterns) to decide whether access should be allowed or not.  

## Features
- Monitors specific paths and mount point in real time  
- Dumps simple stats about file sizes and accesses (CSV output)  
- SQLite-based cache for faster decisions  
- Configurable options, like:
  - `max_file_size_sync_scan` → skip heavy sync scan for very large files  
  - `cache_size` → control how many entries to keep in cache  
  - ...
- Automatically finds optimized configuration options  

## Why?
Because scanning everything on the spot is expensive.  
This way, most real accesses are covered without the system getting stuck.  

## Note
Still experimental, so code and outputs may change around.  

## Build & Run

### Build
The project is built using `Makefile` and `g++`.  
To build the default (release) version, run:
make

The resulting binary `fileguard` will be generated in the project directory.

### Dependencies
- sqlite3  
- pthread  
- hyperscan (libhs)  
- poppler-cpp (via pkg-config)  

Example (Debian/Ubuntu):
sudo apt install libsqlite3-dev libhyperscan-dev libpoppler-cpp-dev pkg-config

### Cache Policy Selection
Cache eviction policies are selected at build time:
- LRU: make lru
- LFU: make lfu
- LFU with file-size awareness: make lfu_size

### Debug Builds
- make debug
- make debug_timing

### Clean
make clean

## Usage

Usage:
  ./fileguard                Run in blocking mode (default)
  ./fileguard statistic      Run in statistic gathering mode
  ./fileguard simulation     Run in simulation mode
  ./fileguard -h, --help     Show this help message

### Execution Modes
- Blocking mode: Real-time file access protection  
- Statistic mode: Collects access statistics for offline analysis  
- Simulation mode: Evaluates policies using recorded traces without affecting the live system
