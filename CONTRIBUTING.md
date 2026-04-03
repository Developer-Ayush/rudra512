# Contributing to Rudra-512

Thank you for your interest in contributing! Here's everything you need to get started.

---

## Ways to Contribute

- **Bug reports** — Found something broken? Open an issue.
- **Feature requests** — Have an idea? Open an issue to discuss it first.
- **Code** — Fix a bug, improve performance, or add a feature.
- **Documentation** — Improve the README, add examples, or fix typos.
- **Benchmarking** — Run the benchmark on different systems and share results.

---

## Before You Start

For anything beyond a small typo fix, please **open an issue first** so we can discuss the approach before you spend time on it. This avoids duplicate work and misaligned expectations.

---

## Development Setup

### Prerequisites

- C++17-compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.15+
- Python 3.8+ with `pybind11` installed
- Node.js 12+

### Clone and Build

```bash
git clone https://github.com/Developer-Ayush/rudra512
cd rudra512
```

**Python bindings:**
```bash
pip install pybind11 scikit-build-core
pip install -e .
```

**Node.js bindings:**
```bash
cd bindings/js
npm install
npm link
```

**C++ CLI only:**
```bash
cmake -B build
cmake --build build
./build/rudra hello
```

---

## Running the Benchmark

```bash
pip install rudra-512-hash
python benchmark.py
```

---

## Making Changes

1. **Fork** the repository on GitHub
2. **Create a branch** from `main`:
   ```bash
   git checkout -b fix/your-bug-description
   # or
   git checkout -b feature/your-feature-name
   ```
3. **Make your changes**
4. **Test your changes** — make sure the bindings still build and basic hashing works
5. **Commit** with a clear message:
   ```bash
   git commit -m "Fix: describe what was broken and how you fixed it"
   # or
   git commit -m "Add: describe the new feature"
   ```
6. **Push** your branch:
   ```bash
   git push origin your-branch-name
   ```
7. **Open a Pull Request** on GitHub against `main`

---

## Pull Request Guidelines

- Keep PRs focused — one fix or feature per PR
- Describe **what** changed and **why** in the PR description
- If your PR fixes an issue, reference it: `Fixes #123`
- All existing functionality must still work after your change

---

## Commit Message Style

Use a short prefix to categorise your commit:

| Prefix | When to use |
|---|---|
| `Fix:` | Bug fix |
| `Add:` | New feature or file |
| `Improve:` | Enhancement to existing feature |
| `Docs:` | Documentation only |
| `Refactor:` | Code change with no behaviour change |
| `Chore:` | Build, CI, dependencies |

---

## Code Style

- **C++:** Follow the existing style. Use `snake_case` for variables and functions, `UPPER_SNAKE_CASE` for constants. Keep lines under 100 characters.
- **Python:** Follow PEP 8.
- **JavaScript:** Use `const`/`let`, no `var`. Prefer arrow functions where appropriate.

---

## Reporting Security Issues

Please **do not** open public issues for security vulnerabilities. See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

---

## Questions?

Open an issue or email: **developerayushanand@gmail.com**
