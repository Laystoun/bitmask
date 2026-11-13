#include <vector>
#include <stdexcept>

#include "base64.hpp"

/* Encode */
#define BASE64_ENCODE_BLOCK(b1, b2, b3) \
    ((static_cast<uint32_t>(b1) << 16) | \
     (static_cast<uint32_t>(b2) << 8)  | \
     static_cast<uint32_t>(b3))

#define EXTRACT_CHUNKS(block, out) do { \
    out[0] = (block >> 18) & 0x3F; \
    out[1] = (block >> 12) & 0x3F; \
    out[2] = (block >> 6 ) & 0x3F; \
    out[3] = (block) & 0x3F; \
} while(0)

/* Decode */
#define BASE64_DECODE_BLOCK(a, b, c, d) \
    ((static_cast<uint32_t>(a) << 18) | \
     (static_cast<uint32_t>(b) << 12) | \
     (static_cast<uint32_t>(c) << 6)  | \
     static_cast<uint32_t>(d))

static const std::string alphabet_base64 = 
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

size_t Base64::encoded_size(size_t inputSize) {
    return ((inputSize + 2) / 3) * 4;
}

std::string Base64::encode(const std::vector<uint8_t>& buf) {
    size_t remainder = buf.size() % 3;
    std::string result; result.reserve(encoded_size(buf.size()));

    for (size_t i = 0; i + 2 < buf.size(); i += 3) {
        uint32_t block = BASE64_ENCODE_BLOCK(buf[i], buf[i + 1], buf[i + 2]);
        uint8_t chunks[4]; EXTRACT_CHUNKS(block, chunks);
        result.push_back(alphabet_base64[chunks[0]]);
        result.push_back(alphabet_base64[chunks[1]]);
        result.push_back(alphabet_base64[chunks[2]]);
        result.push_back(alphabet_base64[chunks[3]]);
    }

    size_t i = buf.size() - remainder;

    if (remainder == 1) {
        uint32_t blocks = BASE64_ENCODE_BLOCK(buf[i], 0 ,0);
        uint8_t chunks[4]; EXTRACT_CHUNKS(blocks, chunks);
        result.push_back(alphabet_base64[chunks[0]]);
        result.push_back(alphabet_base64[chunks[1]]);
        result += "==";
    }

    if (remainder == 2) {
        uint32_t blocks = BASE64_ENCODE_BLOCK(buf[i], buf[i + 1], 0);
        uint8_t chunks[4]; EXTRACT_CHUNKS(blocks, chunks);
        result.push_back(alphabet_base64[chunks[0]]);
        result.push_back(alphabet_base64[chunks[1]]);
        result.push_back(alphabet_base64[chunks[2]]);
        result += "=";
    }

    return result;
}

std::string Base64::decode(const std::string& base64s) {
    if (base64s.empty()) return {};

    if (base64s.size() % 4 != 0) {
        throw std::invalid_argument("Invalid Base64 input");
    }

    std::string result;

    size_t padding = (base64s.back() == '=') +
        (base64s.size() >= 2 && base64s[base64s.size() - 2] == '=');

    result.reserve((base64s.size() / 4) * 3 - padding);

    for (size_t i = 0; i < base64s.size(); i += 4) {
        bool last = (i + 4 == base64s.size());

        bool pad2 = base64s[i + 2] == '=';
        bool pad1 = base64s[i + 3] == '=';

        if ((!last && (pad2 || pad1)) || (pad2 && !pad1)) {
            throw std::invalid_argument("Invalid Base64 padding");
        }

        uint32_t a = BASE64_VALUE(base64s[i]);
        uint32_t b = BASE64_VALUE(base64s[i + 1]);
        uint32_t c = pad2 ? 0 : BASE64_VALUE(base64s[i + 2]);
        uint32_t d = pad1 ? 0 : BASE64_VALUE(base64s[i + 3]);

        uint32_t block = BASE64_DECODE_BLOCK(a, b, c, d);

        result.push_back(static_cast<char>((block >> 16) & 0xFF));

        if (!pad2) {
            result.push_back(static_cast<char>((block >> 8) & 0xFF));
        }

        if (!pad1) {
            result.push_back(static_cast<char>(block & 0xFF));
        }
    }

    return result;
}