import sys
from . import hash_string, hash_file

VERSION = "11.10.11"


def print_help():
    print(f"""
Rudra-512 CLI (v{VERSION})

Usage:
  rudra <text>
  rudra <text> --rounds <n>
  rudra <text> --salt <value>
  rudra --file <path>
  rudra --file <path> --rounds <n>

Options:
  -r, --rounds <n>   Number of rounds (default: 32)
  -s, --salt <val>   Optional salt (string)
  -f, --file <path>  Hash a file instead of text
  -v, --version      Show version
  -h, --help         Show this help message
""")


def main():
    args = sys.argv[1:]

    if not args:
        print_help()
        return

    # -------------------------
    # Quick flags
    # -------------------------
    if "-h" in args or "--help" in args:
        print_help()
        return

    if "-v" in args or "--version" in args:
        print(f"Rudra-512 version {VERSION}")
        return

    rounds = 32
    salt = None
    file_path = None
    text = None

    i = 0
    try:
        while i < len(args):
            arg = args[i]

            # -------------------------
            # ROUNDS
            # -------------------------
            if arg in ("-r", "--rounds"):
                if i + 1 >= len(args):
                    raise ValueError("Missing value for --rounds")
                rounds = int(args[i + 1])
                i += 2

            # -------------------------
            # SALT
            # -------------------------
            elif arg in ("-s", "--salt"):
                if i + 1 >= len(args):
                    raise ValueError("Missing value for --salt")
                salt = args[i + 1]
                i += 2

            # -------------------------
            # FILE
            # -------------------------
            elif arg in ("-f", "--file"):
                if i + 1 >= len(args):
                    raise ValueError("Missing value for --file")
                file_path = args[i + 1]
                i += 2

            # -------------------------
            # UNKNOWN OPTION
            # -------------------------
            elif arg.startswith("-"):
                raise ValueError(f"Unknown option: {arg}")

            # -------------------------
            # TEXT INPUT
            # -------------------------
            else:
                if text is not None:
                    raise ValueError("Multiple input texts provided")
                text = arg
                i += 1

        # -------------------------
        # EXECUTION
        # -------------------------

        if file_path:
            result = hash_file(file_path, rounds, salt)
        else:
            if text is None:
                raise ValueError("No input provided")
            result = hash_string(text, rounds, salt)

        print(result)

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
