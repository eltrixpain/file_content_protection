#include "ContentParser.hpp"
#include <fstream>
#include <iostream>
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#include <memory>



std::string ContentParser::detect_type(const std::string& file_path,
                                       const std::string& raw_content) {
    if (raw_content.rfind("%PDF-", 0) == 0) return "pdf";
    return "text";
}

std::string ContentParser::extract_text(const std::string& type,
                                        const std::string& raw_content)
{
    if (type == "pdf") {
        return extract_text_from_pdf_data(raw_content);
    }
    return raw_content;
}

std::string ContentParser::extract_text_from_pdf_data(const std::string& data) {
    try {
        poppler::byte_array ba;
        ba.assign(data.begin(), data.end());

        std::unique_ptr<poppler::document> doc(
            poppler::document::load_from_data(&ba)
        );
        if (!doc) {
            return data;  // fallback → raw data
        }

        std::string text;
        for (int i = 0; i < doc->pages(); ++i) {
            auto page = doc->create_page(i);
            if (page) {
                auto ustr = page->text().to_utf8();
                text.append(ustr.data(), ustr.size());
                text.push_back('\n');
            }
        }
        return text.empty() ? data : text; // fallback اگر متن خالی شد
    } catch (const std::exception& e) {
        std::cerr << "[ContentParser] poppler error: " << e.what() << std::endl;
        return data; // fallback
    } catch (...) {
        std::cerr << "[ContentParser] unknown poppler error" << std::endl;
        return data; // fallback
    }
}


