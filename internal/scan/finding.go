// Package scan provides static analysis scanners that detect hidden threats
// in source code, including dangerous Unicode, obfuscated payloads,
// polyglot files, blockchain-based C2 patterns, and git history anomalies.
package scan

// Category classifies the type of threat detected by a scanner.
type Category string

// Threat categories returned by the scanners.
const (
	CategoryBidi       Category = "bidi"
	CategoryInvisible  Category = "invisible"
	CategoryHomoglyph  Category = "homoglyph"
	CategoryTag        Category = "tag"
	CategoryNullByte   Category = "null-byte"
	CategoryShebang    Category = "shebang"
	CategoryObfuscate  Category = "obfuscation"
	CategoryPolyglot   Category = "polyglot"
	CategoryExtension  Category = "extension"
	CategoryStegano    Category = "steganography"
	CategoryBlockchain Category = "blockchain-c2"
	CategoryGitAnomaly Category = "git-anomaly"
)

// CategoryOrder defines the display order for category breakdowns in output.
var CategoryOrder = []Category{
	CategoryBidi, CategoryInvisible, CategoryHomoglyph, CategoryTag,
	CategoryNullByte, CategoryShebang, CategoryObfuscate, CategoryPolyglot,
	CategoryExtension, CategoryStegano, CategoryBlockchain, CategoryGitAnomaly,
}

// Finding represents a single detected threat at a specific location.
// Line and Col are 1-indexed. A Line of 0 indicates a file-level finding
// (e.g., filename issues) rather than a content-level one.
type Finding struct {
	File     string
	Line     int
	Col      int
	Category Category
	Detail   string
}

// Results aggregates the outcome of a full scan run.
type Results struct {
	TotalFiles        int
	TotalFindings     int
	FilesWithFindings int
	Counts            map[Category]int
}
