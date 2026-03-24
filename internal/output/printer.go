// Package output formats and prints scan findings to the terminal.
package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/dk/go-sec-lint/internal/scan"
)

const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorRed     = "\033[91m"
	colorGreen   = "\033[92m"
	colorYellow  = "\033[93m"
	colorMagenta = "\033[95m"
	colorCyan    = "\033[96m"
)

var categoryColors = map[scan.Category]string{
	scan.CategoryBidi:       colorRed,
	scan.CategoryInvisible:  colorYellow,
	scan.CategoryHomoglyph:  colorMagenta,
	scan.CategoryTag:        colorCyan,
	scan.CategoryNullByte:   colorRed,
	scan.CategoryShebang:    colorRed,
	scan.CategoryObfuscate:  colorRed,
	scan.CategoryPolyglot:   colorYellow,
	scan.CategoryExtension:  colorYellow,
	scan.CategoryStegano:    colorCyan,
	scan.CategoryBlockchain: colorRed,
	scan.CategoryGitAnomaly: colorYellow,
}

// Printer writes formatted scan results to an output writer.
type Printer struct {
	w     io.Writer
	color bool
}

// New creates a Printer that writes to w. Set color to true to enable
// ANSI color codes in output.
func New(w io.Writer, color bool) *Printer {
	return &Printer{w: w, color: color}
}

// FileFindings prints findings grouped under a file path header.
func (p *Printer) FileFindings(path string, results []scan.Finding) {
	if p.color {
		p.printf("\n%s%s%s\n", colorBold, path, colorReset)
	} else {
		p.printf("\n%s\n", path)
	}
	for _, r := range results {
		p.finding(r)
	}
}

// GitFindings prints findings under a "[git history]" header.
func (p *Printer) GitFindings(findings []scan.Finding) {
	if p.color {
		p.printf("\n%s[git history]%s\n", colorBold, colorReset)
	} else {
		p.printf("\n[git history]\n")
	}
	for _, r := range findings {
		if p.color {
			c := categoryColors[r.Category]
			p.printf("  %s[%s]%s %s\n", c, r.Category, colorReset, r.Detail)
		} else {
			p.printf("  [%s] %s\n", r.Category, r.Detail)
		}
	}
}

// Summary prints the final tally of files scanned and threats found.
func (p *Printer) Summary(res scan.Results) {
	p.printf("\n")
	if res.TotalFindings == 0 {
		label := "No threats detected"
		if p.color {
			p.printf("%s%s%s (%d files scanned)\n", colorGreen, label, colorReset, res.TotalFiles)
		} else {
			p.printf("%s (%d files scanned)\n", label, res.TotalFiles)
		}
		return
	}
	label := fmt.Sprintf("Found %d threat(s) in %d file(s)", res.TotalFindings, res.FilesWithFindings)
	if p.color {
		p.printf("%s%s%s (%d files scanned)\n", colorRed, label, colorReset, res.TotalFiles)
	} else {
		p.printf("%s (%d files scanned)\n", label, res.TotalFiles)
	}
	var parts []string
	for _, cat := range scan.CategoryOrder {
		if c := res.Counts[cat]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, cat))
		}
	}
	p.printf("  Breakdown: %s\n", strings.Join(parts, ", "))
}

func (p *Printer) finding(r scan.Finding) {
	loc := "filename"
	if r.Line > 0 {
		loc = fmt.Sprintf("line %d, col %d", r.Line, r.Col)
	}
	if p.color {
		c := categoryColors[r.Category]
		p.printf("  %s: %s[%s]%s %s\n", loc, c, r.Category, colorReset, r.Detail)
	} else {
		p.printf("  %s: [%s] %s\n", loc, r.Category, r.Detail)
	}
}

// printf wraps fmt.Fprintf, discarding the error. Write errors to
// stdout/stderr are non-actionable in a CLI tool.
func (p *Printer) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(p.w, format, args...)
}
