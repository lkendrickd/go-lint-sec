package scan

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// CodeExtensions lists file extensions recognized as source code or
// configuration. Files with these extensions are included when scanning
// directories.
var CodeExtensions = map[string]bool{
	".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
	".c": true, ".cpp": true, ".cc": true, ".h": true, ".hpp": true,
	".java": true, ".go": true, ".rs": true, ".rb": true, ".php": true,
	".cs": true, ".swift": true, ".kt": true, ".scala": true,
	".sh": true, ".bash": true, ".zsh": true, ".ps1": true, ".bat": true, ".cmd": true,
	".html": true, ".htm": true, ".css": true, ".scss": true, ".less": true,
	".json": true, ".yaml": true, ".yml": true, ".toml": true, ".xml": true,
	".ini": true, ".cfg": true, ".conf": true,
	".sql": true, ".r": true, ".m": true, ".lua": true, ".pl": true, ".pm": true,
	".tf": true, ".hcl": true,
	".md": true, ".rst": true, ".txt": true,
	".mk": true, ".vue": true, ".svelte": true,
}

// skipDirs lists directory names that are skipped during recursive walks.
var skipDirs = map[string]bool{
	".git": true, ".svn": true, ".hg": true, "node_modules": true,
	"__pycache__": true, ".venv": true, "venv": true, ".tox": true,
	".mypy_cache": true, ".pytest_cache": true, "dist": true, "build": true,
	".eggs": true, "vendor": true, "target": true, ".idea": true, ".vscode": true,
}

// isBinaryFile reports whether data appears to be a binary file by checking
// the ratio of non-text bytes in the first 512 bytes. A file with more than
// 10% non-text bytes is considered binary. This avoids the false-negative
// where a single null byte would cause isTextFile to reject the file,
// preventing the null-byte scanner from running.
func isBinaryFile(data []byte) bool {
	size := min(len(data), 512)
	if size == 0 {
		return false
	}
	nonText := 0
	for _, b := range data[:size] {
		if b < 0x08 || (b > 0x0D && b < 0x20 && b != 0x1B) {
			nonText++
		}
	}
	return float64(nonText)/float64(size) > 0.10
}

// File runs all enabled scanners against a single file and returns any
// findings. The checks map controls which scanners run: set individual
// scanner names (e.g., "unicode", "obfuscation") to true for selective
// scanning. Returns an error if the file cannot be read.
func File(filePath string, checks map[string]bool) ([]Finding, error) {
	var findings []Finding

	for _, name := range scannerNames {
		if !checks[name] {
			continue
		}
		if name == "extension" {
			findings = append(findings, ScanFilename(filePath)...)
		}
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return findings, fmt.Errorf("could not read %s: %w", filePath, err)
	}

	if checks["polyglot"] {
		findings = append(findings, ScanPolyglot(data, filePath)...)
	}
	if checks["null-byte"] {
		if !isBinaryFile(data) {
			findings = append(findings, ScanNullBytes(data, filePath)...)
		}
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		if checks["unicode"] {
			findings = append(findings, ScanUnicode(line, lineNum, filePath)...)
		}
		if checks["shebang"] {
			findings = append(findings, ScanShebang(line, lineNum, filePath)...)
		}
		if checks["obfuscation"] {
			findings = append(findings, ScanObfuscation(line, lineNum, filePath)...)
		}
		if checks["steganography"] {
			findings = append(findings, ScanSteganography(line, lineNum, filePath)...)
		}
		if checks["blockchain-c2"] {
			findings = append(findings, ScanBlockchainC2(line, lineNum, filePath)...)
		}
	}

	return findings, nil
}

// scannerNames is the list of all scanner keys, used to normalize the
// "all" check into individual scanner names.
var scannerNames = []string{
	"unicode", "null-byte", "shebang", "obfuscation", "polyglot",
	"extension", "steganography", "blockchain-c2", "git-anomaly",
}

// AllScannerNames returns the list of valid scanner names.
func AllScannerNames() []string {
	return append([]string(nil), scannerNames...)
}

// CollectFiles walks the given paths and returns all files whose extensions
// match the provided set. Directories in [skipDirs] are pruned automatically.
// If a path is a regular file, it is included regardless of extension.
func CollectFiles(paths []string, extensions map[string]bool) []string {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
			continue
		}
		if !info.IsDir() {
			files = append(files, p)
			continue
		}
		_ = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return fs.SkipDir
				}
				return nil
			}
			ext := strings.ToLower(filepath.Ext(d.Name()))
			name := strings.ToLower(d.Name())
			if extensions[ext] || name == "makefile" || name == "dockerfile" {
				files = append(files, path)
			}
			return nil
		})
	}
	return files
}
