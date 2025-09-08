#include "RuleEvaluator.hpp"
#include "ContentParser.hpp"
#include <iostream>
#include <unistd.h>
#include <fcntl.h>
#include <sstream>
#include <cstring>
#include <ctime>
#include <vector>
#include <algorithm>
#include <sys/stat.h>

RuleEvaluator::RuleEvaluator(const ConfigManager& config) : config(config) {}

void RuleEvaluator::handle_event(int fan_fd,
                                 const struct fanotify_event_metadata* metadata,
                                 pid_t logger_pid,
                                 int log_pipe_fd,
                                 int& out_decision) {
    // defaults
    out_decision = 0;      // 0=ALLOW

    if (metadata->fd < 0) return;
    bool allow = true;
    bool is_self = (metadata->pid == logger_pid);

    if (!is_self) {
        // get path
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

        // read whole file
        struct stat st{};
        if (fstat(metadata->fd, &st) == -1 || st.st_size == 0) goto RESPOND;

        std::vector<char> buffer(st.st_size);
        ssize_t done = 0;
        while (done < st.st_size) {
            ssize_t r = pread(metadata->fd, buffer.data() + done, st.st_size - done, done);
            if (r <= 0) break;
            done += r;
        }
        if (done != st.st_size) goto RESPOND;

        std::string header(buffer.data(), std::min<size_t>(5, buffer.size()));
        std::string type = ContentParser::detect_type(path_buf, header);
        std::string extracted = ContentParser::extract_text(type, std::string(buffer.data(), buffer.size()));

        // apply rules
        if (config.matches(extracted)) {
            allow = false;
            out_decision = 1;      // BLOCK

            std::time_t now = std::time(nullptr);
            char* date_time = std::ctime(&now);
            date_time[strlen(date_time) - 1] = '\0'; // strip '\n'

            std::string log_line = "[" + std::string(date_time) + "] BLOCKED: " +
                                   path_buf + " for PID [" + std::to_string(metadata->pid) + "]\n";
            (void)write(log_pipe_fd, log_line.c_str(), log_line.size()); // ignore retval
        }
    }

RESPOND:
    // respond
    struct fanotify_response resp{
        .fd       = metadata->fd,
        .response = allow ? (__u32)FAN_ALLOW : (__u32)FAN_DENY
    };
    (void)write(fan_fd, &resp, sizeof(resp)); // ignore retval
    close(metadata->fd);
}
