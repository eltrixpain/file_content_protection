#pragma once
#include <sys/fanotify.h>
#include <unistd.h>

void start_core_engine(const char* watch_path);
