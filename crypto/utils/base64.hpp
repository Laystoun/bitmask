#include <string>
#include <vector>
#include <cstdint>
#include <iostream>

struct Base64
{
    static std::string encode(const std::vector<uint8_t>& buff);
    static std::string decode(const std::string& base64s);
    static size_t encoded_size(size_t inputSize);

    static uint8_t BASE64_VALUE(unsigned char c) {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;

        throw std::invalid_argument("Invalid Base64 character");
    }
};