package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/dk/go-sec-lint/internal/output"
	"github.com/dk/go-sec-lint/internal/scan"
)

// Build-time variables set via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	noColor := flag.Bool("no-color", false, "disable colored output")
	quiet := flag.Bool("q", false, "only output findings, no summary")
	ext := flag.String("ext", "", "comma-separated additional extensions (e.g. .vue,.svelte)")
	skip := flag.String("skip", "", "comma-separated scanners to skip (e.g. --skip blockchain-c2,steganography)")

	scannerFlags := map[string]*bool{
		"unicode":       flag.Bool("unicode", false, "scan for dangerous Unicode (bidi, invisible, homoglyphs, tags)"),
		"null-byte":     flag.Bool("null-byte", false, "scan for null bytes in text files"),
		"shebang":       flag.Bool("shebang", false, "scan for suspicious shebang lines"),
		"obfuscation":   flag.Bool("obfuscation", false, "scan for obfuscated code (base64, hex, eval)"),
		"polyglot":      flag.Bool("polyglot", false, "scan for polyglot files (mismatched magic bytes)"),
		"extension":     flag.Bool("extension", false, "scan for dangerous double extensions and filename tricks"),
		"steganography": flag.Bool("steganography", false, "scan for hidden data in comments"),
		"blockchain-c2": flag.Bool("blockchain-c2", false, "scan for blockchain C2 patterns (Solana/Ethereum dead-drops)"),
		"git-anomaly":   flag.Bool("git-anomaly", false, "check git history for author/committer date skew (force-push indicator)"),
	}

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "go-sec-lint - scan source code for hidden threats\n\n")
		fmt.Fprintf(os.Stderr, "Usage: go-sec-lint [flags] [paths...]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("go-sec-lint %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	paths := flag.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	checks := buildChecks(scannerFlags, *skip)
	extensions := buildExtensions(*ext)
	printer := output.New(os.Stdout, !*noColor && isTerminal())

	res := runScan(paths, extensions, checks, printer)

	if !*quiet {
		printer.Summary(res)
	}
	if res.TotalFindings > 0 {
		os.Exit(1)
	}
}

// buildChecks resolves scanner flags and skip list into a normalized map
// with one entry per scanner name. If no individual flags are set, all
// scanners are enabled (minus any in skip).
func buildChecks(flags map[string]*bool, skip string) map[string]bool {
	skipped := map[string]bool{}
	if skip != "" {
		for _, s := range strings.Split(skip, ",") {
			skipped[strings.TrimSpace(s)] = true
		}
	}

	// Check if any specific scanner flag was set
	anySpecific := false
	for _, v := range flags {
		if *v {
			anySpecific = true
			break
		}
	}

	checks := map[string]bool{}
	if anySpecific {
		for k, v := range flags {
			if *v && !skipped[k] {
				checks[k] = true
			}
		}
	} else {
		// Enable all scanners minus skipped
		for _, name := range scan.AllScannerNames() {
			if !skipped[name] {
				checks[name] = true
			}
		}
	}
	return checks
}

func buildExtensions(ext string) map[string]bool {
	extensions := make(map[string]bool)
	for k, v := range scan.CodeExtensions {
		extensions[k] = v
	}
	if ext != "" {
		for _, e := range strings.Split(ext, ",") {
			e = strings.TrimSpace(e)
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			extensions[e] = true
		}
	}
	return extensions
}

func runScan(paths []string, extensions, checks map[string]bool, printer *output.Printer) scan.Results {
	files := scan.CollectFiles(paths, extensions)
	res := scan.Results{Counts: map[scan.Category]int{}}

	for _, f := range files {
		res.TotalFiles++
		results, err := scan.File(f, checks)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  warning: %v\n", err)
		}
		if len(results) == 0 {
			continue
		}
		res.FilesWithFindings++
		res.TotalFindings += len(results)
		for _, r := range results {
			res.Counts[r.Category]++
		}
		printer.FileFindings(f, results)
	}

	if checks["git-anomaly"] {
		for _, p := range paths {
			gitFindings, err := scan.ScanGitAnomalies(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  warning: git scan: %v\n", err)
			}
			if len(gitFindings) > 0 {
				res.TotalFindings += len(gitFindings)
				res.FilesWithFindings++
				for _, r := range gitFindings {
					res.Counts[r.Category]++
				}
				printer.GitFindings(gitFindings)
			}
		}
	}

	return res
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
