// === src/CoreEngine/CoreEngine.cpp ===
#include "CoreEngine.hpp"
#include "Logger.hpp"
#include "ConfigManager.hpp" 

#include <iostream>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstring>
#include <cstdlib>


#define BUF_SIZE 4096
#define LOG_PATH "/tmp/fileguard.log"

void handle_event(int fan_fd, const fanotify_event_metadata* metadata, pid_t logger_pid, int log_pipe_fd, const ConfigManager& config)
 {
    if (metadata->fd < 0) return;
    bool allow = true;
    bool is_self = (metadata->pid == logger_pid);

    if (!is_self) {
        char fd_link[64];
        snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", metadata->fd);
        char path_buf[512];
        ssize_t n = readlink(fd_link, path_buf, sizeof(path_buf) - 1);
        if (n >= 0) {
            path_buf[n] = '\0';
            std::cout << "path  : " << path_buf << "  access by " << metadata->pid << "\n";
        }

        lseek(metadata->fd, 0, SEEK_SET);
        char content[2048] = {0};
        ssize_t size_of_read = read(metadata->fd, content, sizeof(content));
        if (size_of_read > 0 && config.matches(content)) {
            allow = false;
            std::string log_entry = std::to_string(metadata->pid) + " BLOCKED: " + path_buf + "\n";
            write(log_pipe_fd, log_entry.c_str(), log_entry.size());
        }
    }

    struct fanotify_response resp {
        .fd = metadata->fd,
        .response = allow ? (__u32)FAN_ALLOW : (__u32)FAN_DENY
    };
    write(fan_fd, &resp, sizeof(resp));
    close(metadata->fd);
}

void start_core_engine(const ConfigManager& config) {
    std::string watch_path = config.getWatchPath();
    int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
    if (fan_fd == -1) { perror("fanotify_init"); exit(1); }

    if (fanotify_mark(fan_fd, FAN_MARK_ADD, FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, AT_FDCWD, watch_path.c_str()) == -1) {
        perror("fanotify_mark"); exit(1);
    }

    int log_pipe[2];
    if (pipe(log_pipe) == -1) { perror("pipe"); exit(1); }

    pid_t logger_pid = fork();
    if (logger_pid == -1) { perror("fork"); exit(1); }

    if (logger_pid == 0) {
        close(log_pipe[1]);
        logger_loop(log_pipe[0]);
        exit(0);
    }



    std::cout << "[CoreEngine] Watching " << watch_path << " for access events...\n";

    char buffer[BUF_SIZE];
    struct fanotify_event_metadata* metadata;

    while (true) {
        ssize_t len = read(fan_fd, buffer, sizeof(buffer));
        if (len <= 0) continue;
        metadata = (struct fanotify_event_metadata*)buffer;
        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                std::cerr << "Mismatched fanotify version!" << std::endl;
                exit(1);
            }
            handle_event(fan_fd, metadata, logger_pid, log_pipe[1],config);
            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }
}
