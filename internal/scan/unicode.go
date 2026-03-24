package scan

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// bidiChars maps bidirectional override/embedding characters to their
// Unicode names. These characters can reorder displayed text, enabling
// Trojan Source attacks (CVE-2021-42574).
var bidiChars = map[rune]string{
	0x202A: "LEFT-TO-RIGHT EMBEDDING",
	0x202B: "RIGHT-TO-LEFT EMBEDDING",
	0x202C: "POP DIRECTIONAL FORMATTING",
	0x202D: "LEFT-TO-RIGHT OVERRIDE",
	0x202E: "RIGHT-TO-LEFT OVERRIDE",
	0x2066: "LEFT-TO-RIGHT ISOLATE",
	0x2067: "RIGHT-TO-LEFT ISOLATE",
	0x2068: "FIRST STRONG ISOLATE",
	0x2069: "POP DIRECTIONAL ISOLATE",
	0x200F: "RIGHT-TO-LEFT MARK",
	0x200E: "LEFT-TO-RIGHT MARK",
}

// invisibleChars maps zero-width and other invisible characters to their
// Unicode names. These can hide payloads inside otherwise normal-looking code.
var invisibleChars = map[rune]string{
	0x200B: "ZERO WIDTH SPACE",
	0x200C: "ZERO WIDTH NON-JOINER",
	0x200D: "ZERO WIDTH JOINER",
	0xFEFF: "ZERO WIDTH NO-BREAK SPACE (BOM)",
	0x00AD: "SOFT HYPHEN",
	0x034F: "COMBINING GRAPHEME JOINER",
	0x061C: "ARABIC LETTER MARK",
	0x115F: "HANGUL CHOSEONG FILLER",
	0x1160: "HANGUL JUNGSEONG FILLER",
	0x17B4: "KHMER VOWEL INHERENT AQ",
	0x17B5: "KHMER VOWEL INHERENT AA",
	0x180E: "MONGOLIAN VOWEL SEPARATOR",
	0x2060: "WORD JOINER",
	0x2061: "FUNCTION APPLICATION",
	0x2062: "INVISIBLE TIMES",
	0x2063: "INVISIBLE SEPARATOR",
	0x2064: "INVISIBLE PLUS",
	0xFFA0: "HALFWIDTH HANGUL FILLER",
}

type homoglyphEntry struct {
	lookalike byte
	name      string
}

// homoglyphs maps characters that are visually confusable with common
// ASCII letters (e.g., Cyrillic 'а' U+0430 vs Latin 'a' U+0061).
// These enable identifier spoofing and phishing in source code.
var homoglyphs = map[rune]homoglyphEntry{
	// Cyrillic
	0x0410: {'A', "CYRILLIC CAPITAL A"},
	0x0412: {'B', "CYRILLIC CAPITAL VE"},
	0x0421: {'C', "CYRILLIC CAPITAL ES"},
	0x0415: {'E', "CYRILLIC CAPITAL IE"},
	0x041D: {'H', "CYRILLIC CAPITAL EN"},
	0x041A: {'K', "CYRILLIC CAPITAL KA"},
	0x041C: {'M', "CYRILLIC CAPITAL EM"},
	0x041E: {'O', "CYRILLIC CAPITAL O"},
	0x0420: {'P', "CYRILLIC CAPITAL ER"},
	0x0422: {'T', "CYRILLIC CAPITAL TE"},
	0x0425: {'X', "CYRILLIC CAPITAL HA"},
	0x0430: {'a', "CYRILLIC SMALL A"},
	0x0435: {'e', "CYRILLIC SMALL IE"},
	0x043E: {'o', "CYRILLIC SMALL O"},
	0x0440: {'p', "CYRILLIC SMALL ER"},
	0x0441: {'c', "CYRILLIC SMALL ES"},
	0x0443: {'y', "CYRILLIC SMALL U"},
	0x0445: {'x', "CYRILLIC SMALL HA"},
	0x0455: {'s', "CYRILLIC SMALL DZE"},
	0x0456: {'i', "CYRILLIC SMALL I"},
	0x0458: {'j', "CYRILLIC SMALL JE"},
	// Greek
	0x0391: {'A', "GREEK CAPITAL ALPHA"},
	0x0392: {'B', "GREEK CAPITAL BETA"},
	0x0395: {'E', "GREEK CAPITAL EPSILON"},
	0x0397: {'H', "GREEK CAPITAL ETA"},
	0x0399: {'I', "GREEK CAPITAL IOTA"},
	0x039A: {'K', "GREEK CAPITAL KAPPA"},
	0x039C: {'M', "GREEK CAPITAL MU"},
	0x039D: {'N', "GREEK CAPITAL NU"},
	0x039F: {'O', "GREEK CAPITAL OMICRON"},
	0x03A1: {'P', "GREEK CAPITAL RHO"},
	0x03A4: {'T', "GREEK CAPITAL TAU"},
	0x03A5: {'Y', "GREEK CAPITAL UPSILON"},
	0x03A7: {'X', "GREEK CAPITAL CHI"},
	0x03BF: {'o', "GREEK SMALL OMICRON"},
}

// dangerousSecondExt lists file extensions that indicate an executable
// when they appear as the final extension in a multi-extension filename.
var dangerousSecondExt = map[string]bool{
	".exe": true, ".bat": true, ".cmd": true, ".com": true, ".scr": true,
	".pif": true, ".js": true, ".vbs": true, ".ps1": true, ".sh": true,
	".py": true, ".rb": true, ".pl": true,
}

// ScanUnicode inspects a single line for bidirectional overrides, invisible
// characters, homoglyphs, and Unicode tag characters.
func ScanUnicode(line string, lineNum int, filePath string) []Finding {
	var findings []Finding
	col := 0
	for i := 0; i < len(line); {
		r, size := utf8.DecodeRuneInString(line[i:])
		col++
		if r == utf8.RuneError && size == 1 {
			i += size
			continue
		}

		if name, ok := bidiChars[r]; ok {
			findings = append(findings, Finding{
				File: filePath, Line: lineNum, Col: col,
				Category: CategoryBidi,
				Detail:   fmt.Sprintf("U+%04X %s", r, name),
			})
		} else if name, ok := invisibleChars[r]; ok {
			findings = append(findings, Finding{
				File: filePath, Line: lineNum, Col: col,
				Category: CategoryInvisible,
				Detail:   fmt.Sprintf("U+%04X %s", r, name),
			})
		} else if entry, ok := homoglyphs[r]; ok {
			findings = append(findings, Finding{
				File: filePath, Line: lineNum, Col: col,
				Category: CategoryHomoglyph,
				Detail:   fmt.Sprintf("U+%04X %s (looks like '%c')", r, entry.name, entry.lookalike),
			})
		} else if r >= 0xE0001 && r <= 0xE007F {
			findings = append(findings, Finding{
				File: filePath, Line: lineNum, Col: col,
				Category: CategoryTag,
				Detail:   fmt.Sprintf("U+%04X TAG CHARACTER", r),
			})
		}

		i += size
	}
	return findings
}

// ScanNullBytes scans raw file bytes for null (0x00) bytes that should not
// appear in text-based source files. Null bytes can be used for injection
// attacks in languages and tools that treat them as string terminators.
func ScanNullBytes(data []byte, filePath string) []Finding {
	var findings []Finding
	lineNum := 1
	col := 0
	for i, b := range data {
		col++
		if b == '\n' {
			lineNum++
			col = 0
			continue
		}
		if b == 0 {
			findings = append(findings, Finding{
				File: filePath, Line: lineNum, Col: col,
				Category: CategoryNullByte,
				Detail:   fmt.Sprintf("NULL byte (0x00) at offset %d", i),
			})
		}
	}
	return findings
}

// ScanFilename checks a file's name for null bytes, bidirectional overrides
// (extension spoofing), non-printable characters, and dangerous double
// extensions like "readme.txt.exe".
func ScanFilename(filePath string) []Finding {
	var findings []Finding
	base := filepath.Base(filePath)

	if strings.ContainsRune(base, 0) {
		findings = append(findings, Finding{
			File: filePath, Line: 0, Col: 0,
			Category: CategoryNullByte,
			Detail:   "null byte in filename",
		})
	}

	if strings.ContainsRune(base, 0x202E) {
		findings = append(findings, Finding{
			File: filePath, Line: 0, Col: 0,
			Category: CategoryBidi,
			Detail:   "RIGHT-TO-LEFT OVERRIDE in filename (extension spoofing)",
		})
	}

	for _, r := range base {
		if !unicode.IsPrint(r) && r != 0 {
			findings = append(findings, Finding{
				File: filePath, Line: 0, Col: 0,
				Category: CategoryInvisible,
				Detail:   fmt.Sprintf("non-printable character U+%04X in filename", r),
			})
			break
		}
	}

	trimmed := strings.TrimPrefix(base, ".")
	parts := strings.Split(trimmed, ".")
	if len(parts) >= 3 {
		lastExt := "." + strings.ToLower(parts[len(parts)-1])
		if dangerousSecondExt[lastExt] {
			findings = append(findings, Finding{
				File: filePath, Line: 0, Col: 0,
				Category: CategoryExtension,
				Detail:   fmt.Sprintf("double extension hiding executable: %s", strings.ToLower(base)),
			})
		}
	}
	return findings
}
