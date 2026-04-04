# Security Policy

## Supported Versions

| Version | Supported |
|---|---|
| 2.0.x | ✅ Yes |

Only the latest release receives security fixes. Please update to the latest version before reporting an issue.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you discover a vulnerability in Rudra-512, email directly:

📧 **developerayushanand@gmail.com**

Include in your report:
- A clear description of the vulnerability
- Steps to reproduce it
- The potential impact
- Any suggested fix (optional but appreciated)

You will receive an acknowledgement within **48 hours** and a resolution update within **7 days**.

## Important Disclaimer

> Rudra-512 is a custom, experimental cryptographic hash function. It has **not** undergone formal third-party cryptanalysis or a professional security audit. For production security-critical systems, established standards like SHA-2, SHA-3, or BLAKE3 are strongly recommended.

## Scope

The following are in scope for security reports:

- Hash collisions or near-collisions
- Weaknesses in the avalanche or diffusion properties
- Salt handling vulnerabilities
- Bugs in the C++ core that could cause undefined behavior (buffer overflows, etc.)
- Issues in the Python or Node.js bindings that expose unsafe behaviour

The following are **out of scope:**

- Issues in dependencies (pybind11, Node-API) — please report those upstream
- Performance concerns that are not security-related
- The intentional speed reduction (GPU resistance) — this is by design
