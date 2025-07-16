#include "ContentParser.hpp"
#include <fstream>
#include <iostream>
#include <poppler/cpp/poppler-document.h>
#include <poppler/cpp/poppler-page.h>
#include <memory>


std::string ContentParser::detect_type(const std::string& file_path, const std::string& raw_content) {
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
    poppler::byte_array ba;
    ba.assign(data.begin(), data.end());  

    poppler::document* raw = poppler::document::load_from_data(&ba);  
    if (!raw) return "";

    std::shared_ptr<poppler::document> doc(raw);

    std::string text;
    for (int i = 0; i < doc->pages(); ++i) {
        auto page = doc->create_page(i);
        if (page) {
            text += std::string(page->text().to_utf8().data());
            text += "\n";
        }
    }
    return text;
}
