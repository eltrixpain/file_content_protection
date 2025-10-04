#include "ContentParser.hpp"
#include <memory>
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#include <ctime>
#include <unistd.h>
#include <cstring>


// Desc: write a timestamped Poppler error line to a log pipe
// In: const char* msg, int log_pipe_fd
// Out: void
static inline void log_poppler_error(const char* msg, int log_pipe_fd) {
    std::time_t now = std::time(nullptr);
    char* dt = std::ctime(&now);
    if (dt) dt[strlen(dt)-1] = '\0'; // remove \n

    std::string line = "[" + std::string(dt) + "] [ContentParser] poppler error: "
                     + msg + "\n";
    ssize_t _wr = ::write(log_pipe_fd, line.c_str(), line.size());
    (void)_wr;
}

// Desc: detect content type from raw bytes ("%PDF-" => "pdf")
// In: const std::string& raw_content
// Out: std::string ("pdf" or "text")
std::string ContentParser::detect_type(const std::string& raw_content) {
    if (raw_content.rfind("%PDF-", 0) == 0) return "pdf";
    return "text";
}

// Desc: extract text based on type (PDF via Poppler, else passthrough)
// In: const std::string& type, const std::string& raw_content, int log_pipe_fd
// Out: std::string (extracted or original text)
std::string ContentParser::extract_text(const std::string& type,
                                        const std::string& raw_content,
                                        int log_pipe_fd) {
    if (type == "pdf") {
        return extract_text_from_pdf_data(raw_content, log_pipe_fd);
    }
    return raw_content;
}

// Desc: extract text from in-memory PDF data; log errors; fallback to raw
// In: const std::string& data, int log_pipe_fd
// Out: std::string (PDF text or original data on failure)
std::string ContentParser::extract_text_from_pdf_data(const std::string& data,
                                                      int log_pipe_fd) {
    try {
        poppler::byte_array ba;
        ba.assign(data.begin(), data.end());

        std::unique_ptr<poppler::document> doc(
            poppler::document::load_from_data(&ba)
        );
        if (!doc) {
            log_poppler_error("load_from_data failed", log_pipe_fd);
            return data;
        }

        std::string text;
        const int pages = doc->pages();
        for (int i = 0; i < pages; ++i) {
            auto page = doc->create_page(i);
            if (!page) continue;

        auto u = page->text().to_utf8();     // u: poppler::byte_array = std::vector<char>
        if (!u.empty()) {
            text.append(u.begin(), u.end());
            text.push_back('\n');
        }
        }
        if (text.empty()) {
            log_poppler_error("empty extraction result", log_pipe_fd);
            return data;
        }
        return text;
    } catch (const std::exception& e) {
        log_poppler_error(e.what(), log_pipe_fd);
        return data;
    } catch (...) {
        log_poppler_error("unknown exception", log_pipe_fd);
        return data;
    }
}
