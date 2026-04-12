#!/usr/bin/env node

const rudra = require('./');
const fs = require('fs');

const VERSION = "11.10.10";

function printHelp() {
  console.log(`
Rudra-512 CLI (v${VERSION})

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
`);
}

function main() {
  const args = process.argv.slice(2);

  if (!args.length) {
    printHelp();
    return;
  }

  if (args.includes("-h") || args.includes("--help")) {
    printHelp();
    return;
  }

  if (args.includes("-v") || args.includes("--version")) {
    console.log(`Rudra-512 version ${VERSION}`);
    return;
  }

  let rounds = 32;
  let salt = null;
  let filePath = null;
  let text = null;

  let i = 0;

  try {
    while (i < args.length) {
      const arg = args[i];

      if (arg === "-r" || arg === "--rounds") {
        if (i + 1 >= args.length) throw new Error("Missing value for --rounds");
        rounds = parseInt(args[i + 1]);
        i += 2;
      } else if (arg === "-s" || arg === "--salt") {
        if (i + 1 >= args.length) throw new Error("Missing value for --salt");
        salt = args[i + 1];
        i += 2;
      } else if (arg === "-f" || arg === "--file") {
        if (i + 1 >= args.length) throw new Error("Missing value for --file");
        filePath = args[i + 1];
        i += 2;
      } else if (arg.startsWith("-")) {
        throw new Error(`Unknown option: ${arg}`);
      } else {
        if (text !== null) throw new Error("Multiple input texts provided");
        text = arg;
        i += 1;
      }
    }

    let result;

    if (filePath) {
      if (!fs.existsSync(filePath)) throw new Error("File not found");
      const data = fs.readFileSync(filePath, "utf-8");
      result = rudra.hash(data, rounds);
    } else {
      if (!text) throw new Error("No input provided");
      result = rudra.hash(text, rounds);
    }

    console.log(result);

  } catch (err) {
    console.error(`Error: ${err.message}`);
    process.exit(1);
  }
}

main();
