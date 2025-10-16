
#include <string>

class ContentParser {
public:
    static std::string detect_type(const std::string& raw_content);

    static std::string extract_text(const std::string& type,
                                    const std::string& file_path,
                                    const std::string& raw_content,
                                    int log_pipe_fd);
};

