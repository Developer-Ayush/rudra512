#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include "rudra512.h"

#ifndef RUDRA_VERSION
#define RUDRA_VERSION "dev"
#endif

void print_usage() {
    std::cout << "Rudra-512 CLI\n\n";
    std::cout << "Usage:\n";
    std::cout << "  rudra <text>\n";
    std::cout << "  rudra <text> --rounds N\n";
    std::cout << "  rudra <text> --salt VALUE\n";
    std::cout << "  rudra --file <path>\n";
    std::cout << "  rudra --file <path> --rounds N --salt VALUE\n\n";

    std::cout << "Options:\n";
    std::cout << "  --rounds N     Number of rounds (default: 32)\n";
    std::cout << "  --salt VALUE   Use custom salt\n";
    std::cout << "  --file PATH    Hash file instead of text\n";
    std::cout << "  --version, -v  Show version\n";
    std::cout << "  --help, -h     Show this help message\n";
}

std::string read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open file");
    }

    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

int main(int argc, char* argv[]) {
    try {
        if (argc < 2) {
            print_usage();
            return 0;
        }

        std::string input;
        std::string file_path;
        int rounds = 32;
        std::string salt_value;
        bool use_salt = false;

        // -------------------------
        // Parse arguments
        // -------------------------
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];

            if (arg == "--help" || arg == "-h") {
                print_usage();
                return 0;
            }
            else if (arg == "--version" || arg == "-v") {
                std::cout << "Rudra-512 version " << RUDRA_VERSION << std::endl;
                return 0;
            }
            else if (arg == "--rounds") {
                if (i + 1 >= argc) throw std::runtime_error("Missing rounds value");
                rounds = std::stoi(argv[++i]);
            }
            else if (arg == "--salt") {
                if (i + 1 >= argc) throw std::runtime_error("Missing salt value");
                salt_value = argv[++i];
                use_salt = true;
            }
            else if (arg == "--file") {
                if (i + 1 >= argc) throw std::runtime_error("Missing file path");
                file_path = argv[++i];
            }
            else {
                input = arg;
            }
        }

        // -------------------------
        // Determine input
        // -------------------------
        std::string data;

        if (!file_path.empty()) {
            data = read_file(file_path);
        } else if (!input.empty()) {
            data = input;
        } else {
            throw std::runtime_error("No input provided");
        }

        // -------------------------
        // Hash
        // -------------------------
        std::string result;

        if (use_salt) {
            result = rudra::hash_string(data, rounds, &salt_value);
        } else {
            result = rudra::hash_string(data, rounds, nullptr);
        }

        std::cout << result << std::endl;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
