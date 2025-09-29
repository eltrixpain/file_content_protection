# file_content_protection  

A small tool for protecting file contents on UNIX-based systems.  
It watches file accesses (using fanotify) and checks them against rules (like regex patterns) to decide whether access should be allowed or not.  

## Features
- Monitors specific paths and mount point in real time  
- Dumps simple stats about file sizes and accesses (CSV output)  
- SQLite-based cache for faster decisions  
- Configurable option, like:
  - `max_file_size_sync_scan` → skip heavy sync scan for very large files  
  - `cache_size` → control how many entries to keep in cache  
  - ...
- Finding optimized config option autmotically
## Why?
Because scanning everything on the spot is expensive.  
This way, most real accesses are covered without the system getting stuck.  

## Note
Still experimental, so code and outputs may change around.  

