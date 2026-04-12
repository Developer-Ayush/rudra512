
#ifndef RUDRA512_H
#define RUDRA512_H

#include <string>

namespace rudra {

    std::string hash_string(
        const std::string& input,
        int rounds = 32,
        const std::string* salt = nullptr
    );

    std::string hash_file(
        const std::string& filename,
        int rounds = 32,
        const std::string* salt = nullptr
    );

}

#endif