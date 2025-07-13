#include <iostream>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <fcntl.h>
#include <sys/fanotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <poll.h>

#define BUF_SIZE 4096

void handle_event(int fan_fd, const fanotify_event_metadata* metadata,pid_t self_pid)
{   
    
    std::cout << "[DEBUG] handle_event() called\n";
    std::cout << "=== Fanotify Event ===\n";
    std::cout << "  event_len : " << metadata->event_len << '\n';
    std::cout << "  vers      : " << static_cast<int>(metadata->vers) << '\n';
    std::cout << "  pid       : " << metadata->pid << '\n';
    std::cout << "  fd        : " << metadata->fd << '\n';
    std::cout << "  mask      : 0x" << std::hex << metadata->mask << std::dec << "\n";
    bool allow = true;  
    if (metadata->pid == self_pid){
        std::cout << "your process\n";
    }
    if (metadata->fd >= 0) {
        // ---- Resolve FD -> real path ----
        char fd_link[64];
        snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", metadata->fd);

        char path_buf[512];
        ssize_t n = readlink(fd_link, path_buf, sizeof(path_buf) - 1);
        if (n >= 0) {
            path_buf[n] = '\0';
            std::cout << "  path      : " << path_buf << '\n';
        } else {
            perror("  readlink");
        }

        // Check if the content include SECRET block the open access 
        lseek(metadata->fd, 0, SEEK_SET);
        char content[2048] = {0};
        ssize_t size_of_read = read(metadata->fd, content, sizeof(content));
        if (size_of_read > 0 && std::strstr(content, "SECRET") != nullptr) {
                allow = false;   
        }

        // ---- Mandatory permission response ----
        struct fanotify_response resp {
            .fd       = metadata->fd,
            .response = allow ? (__u32)FAN_ALLOW : (__u32)FAN_DENY        
        };
        if (write(fan_fd, &resp, sizeof(resp)) != sizeof(resp)) {
            perror("  write(FAN_ALLOW)");
        }

        close(metadata->fd);               
    }
    std::cout << "=======================\n";
}



int main() {
    const pid_t SELF_PID = getpid();
    int fan_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY | O_LARGEFILE);
    if (fan_fd == -1) {
        perror("fanotify_init");
        return EXIT_FAILURE;
    }

    // Monitor /home for testing
    if (fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_ONLYDIR,
                      FAN_OPEN_PERM | FAN_EVENT_ON_CHILD, AT_FDCWD, "/home/liarokan/Desktop/project_university") == -1) {
        perror("fanotify_mark");
        return EXIT_FAILURE;
    }

    std::cout << "[CoreEngine] Watching /home for access events..." << std::endl;

    char buffer[BUF_SIZE];
    struct fanotify_event_metadata* metadata;

    while (true) {
        ssize_t len = read(fan_fd, buffer, sizeof(buffer));
        if (len <= 0) continue;

        metadata = (struct fanotify_event_metadata*)buffer;

        while (FAN_EVENT_OK(metadata, len)) {
            if (metadata->vers != FANOTIFY_METADATA_VERSION) {
                std::cerr << "Mismatched fanotify version!" << std::endl;
                return EXIT_FAILURE;
            }

            if (metadata->fd >= 0) {
                handle_event(fan_fd , metadata, SELF_PID);
            }

            metadata = FAN_EVENT_NEXT(metadata, len);
        }
    }

    return EXIT_SUCCESS;
}
