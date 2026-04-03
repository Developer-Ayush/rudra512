#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "rudra512.h"

namespace py = pybind11;

// -------------------------
// Wrapper: hash_string
// -------------------------
py::str py_hash_string(
    const std::string& input,
    int rounds = 32,
    py::object salt = py::none()
) {
    // No salt
    if (salt.is_none()) {
        return rudra::hash_string(input, rounds, nullptr);
    }

    // Salt must be string
    if (!py::isinstance<py::str>(salt)) {
        throw std::invalid_argument("Salt must be a string or None");
    }

    std::string salt_str = salt.cast<std::string>();
    return rudra::hash_string(input, rounds, &salt_str);
}

// -------------------------
// Wrapper: hash_file
// -------------------------
py::str py_hash_file(
    const std::string& path,
    int rounds = 32,
    py::object salt = py::none()
) {
    // No salt
    if (salt.is_none()) {
        return rudra::hash_file(path, rounds, nullptr);
    }

    // Salt must be string
    if (!py::isinstance<py::str>(salt)) {
        throw std::invalid_argument("Salt must be a string or None");
    }

    std::string salt_str = salt.cast<std::string>();
    return rudra::hash_file(path, rounds, &salt_str);
}

// -------------------------
// Module definition
// -------------------------
PYBIND11_MODULE(_rudra512, m) {
    m.doc() = "Rudra-512 hashing library";

    m.def(
        "hash_string",
        &py_hash_string,
        py::arg("data"),
        py::arg("rounds") = 32,
        py::arg("salt") = py::none(),
        "Hash a string using Rudra-512"
    );

    m.def(
        "hash_file",
        &py_hash_file,
        py::arg("path"),
        py::arg("rounds") = 32,
        py::arg("salt") = py::none(),
        "Hash a file using Rudra-512"
    );
}
