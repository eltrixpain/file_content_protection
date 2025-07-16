#include "RuleEvaluator.hpp"
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <sstream>
#include <cstring>
#include <ctime>

RuleEvaluator::RuleEvaluator(const ConfigManager& config) : config(config) {}

void RuleEvaluator::handle_event(int fan_fd, const struct fanotify_event_metadata* metadata, pid_t logger_pid, int log_pipe_fd) {
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
        } else {
            strncpy(path_buf, "[unknown]", sizeof(path_buf));
        }

        lseek(metadata->fd, 0, SEEK_SET);
        char content[2048] = {0};
        ssize_t size_of_read = read(metadata->fd, content, sizeof(content));
        if (size_of_read > 0 && config.matches(content)) {
            allow = false;
            std::time_t now = std::time(0);
            char* date_time = std::ctime(&now);
            date_time[strlen(date_time) - 1] = '\0';
            std::string log_line = "[" + std::string(date_time) + "] BLOCKED: " + path_buf + " for PID [" + std::to_string(metadata->pid)  + "]\n";
            write(log_pipe_fd, log_line.c_str(), log_line.size());
        }
    }

    struct fanotify_response resp {
        .fd = metadata->fd,
        .response = allow ? (__u32)FAN_ALLOW : (__u32)FAN_DENY
    };
    write(fan_fd, &resp, sizeof(resp));
    close(metadata->fd);
}
