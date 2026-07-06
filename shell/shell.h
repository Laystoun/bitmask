#ifndef SHELL_H
#define SHELL_H

#include <string>

struct flags {
    bool verbose;
    bool debug;
    bool monitor;

    bool encrypt;
    bool decrypt;
    bool password;

    std::string password;
    std::string crypt_path;
};

#endif