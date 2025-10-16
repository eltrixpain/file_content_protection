#include "ContentParser.hpp"
#include <memory>
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#include <ctime>
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>


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

// Desc: extract text from in-memory PDF data; log errors; fallback to raw
// In: const std::string& data, int log_pipe_fd
// Out: std::string (PDF text or original data on failure)
static std::string extract_text_from_pdf_data(const std::string& data,
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


static std::string extract_text_from_doc_data(
    const std::string& file_path,
    int log_pipe_fd)
{
    namespace fs = std::filesystem;

    try {
        if (file_path.empty() || !fs::exists(file_path)) {
            log_poppler_error("invalid file path", log_pipe_fd);
            return {};
        }

        if (std::system("command -v libreoffice >/dev/null 2>&1") != 0) {
            log_poppler_error("libreoffice not installed", log_pipe_fd);
            return {};
        }

        std::string tmpdir_tmpl = (fs::temp_directory_path() / "cpXXXXXX").string();
        std::vector<char> buf(tmpdir_tmpl.begin(), tmpdir_tmpl.end());
        buf.push_back('\0');
        char* tmpdir = mkdtemp(buf.data());
        if (!tmpdir) {
            log_poppler_error("mkdtemp failed", log_pipe_fd);
            return {};
        }

        fs::path tmpdir_path(tmpdir);
        std::string filename = fs::path(file_path).filename().string();
        fs::path out_txt = tmpdir_path / (filename + ".txt");
        fs::path err_file = tmpdir_path / "stderr.txt";

        std::string cmd = "libreoffice --headless --convert-to txt:Text \"" +
            file_path + "\" --outdir \"" + tmpdir_path.string() +
            "\" 2>\"" + err_file.string() + "\"";
        std::system(cmd.c_str());

        if (!fs::exists(out_txt)) {
            if (fs::exists(err_file)) {
                std::ifstream e(err_file);
                std::string err((std::istreambuf_iterator<char>(e)), {});
                log_poppler_error(("convert failed: " + err).c_str(), log_pipe_fd);
            } else {
                log_poppler_error("no output file", log_pipe_fd);
            }
            fs::remove_all(tmpdir_path);
            return {};
        }

        std::ifstream in(out_txt);
        std::string result((std::istreambuf_iterator<char>(in)), {});
        fs::remove_all(tmpdir_path);
        return result;
    } catch (const std::exception& e) {
        log_poppler_error(e.what(), log_pipe_fd);
        return {};
    } catch (...) {
        log_poppler_error("unknown exception", log_pipe_fd);
        return {};
    }
}



// Desc: detect content type from raw bytes ("%PDF-" => "pdf")
// In: const std::string& raw_content
// Out: std::string ("pdf" or "text")
std::string ContentParser::detect_type(const std::string& raw_content) {
    if (raw_content.rfind("%PDF-", 0) == 0) return "pdf";
    if (raw_content.rfind("PK", 0) == 0) return "docx";  // ZIP signature
    return "text";
}

// Desc: extract text based on type (PDF via Poppler, else passthrough)
// In: const std::string& type, const std::string& raw_content, int log_pipe_fd
// Out: std::string (extracted or original text)
std::string ContentParser::extract_text(const std::string& type,
                                        const std::string& file_path,
                                        const std::string& raw_content,
                                        int log_pipe_fd) {
    if (type == "pdf") {
        return extract_text_from_pdf_data(raw_content, log_pipe_fd);
    }
    if (type == "doc" || type == "docx") {
        return extract_text_from_doc_data(file_path, log_pipe_fd);
    }
    return raw_content;
}
