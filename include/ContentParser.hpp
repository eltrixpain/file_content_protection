#ifndef CONTENT_PARSER_HPP
#define CONTENT_PARSER_HPP

#include <string>

class ContentParser {
public:
    static std::string detect_type(const std::string& raw_content);

    static std::string extract_text(const std::string& type,
                                    const std::string& raw_content,
                                    int log_pipe_fd);

    static std::string extract_text_from_pdf_data(const std::string& data,
                                                  int log_pipe_fd);
};

#endif // CONTENT_PARSER_HPP
