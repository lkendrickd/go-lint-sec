package scan

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	reBase64Pipe = regexp.MustCompile(`(?i)(base64\s+(-d|--decode)|base64_decode|atob|b64decode)\s*[^;]*\s*\|\s*(sh|bash|zsh|eval|exec|system|python|perl|ruby|node)`)
	reEvalBase64 = regexp.MustCompile(`(?i)(eval|exec|system|os\.system|subprocess|Process\.Start)\s*\(\s*[^)]*?(base64|atob|b64decode|decode\s*\()`)
	reHexExec    = regexp.MustCompile(`(?i)(\\x[0-9a-f]{2}){8,}`)
	reOctalExec  = regexp.MustCompile(`(?i)(\\[0-3][0-7]{2}){8,}`)
	reLongBase64 = regexp.MustCompile(`[A-Za-z0-9+/]{100,}={0,2}`)
	reEvalConcat = regexp.MustCompile(`(?i)(eval|exec)\s*\(\s*['"]\s*\+|` +
		`(eval|exec)\s*\(\s*chr\s*\(|` +
		`(eval|exec)\s*\(\s*String\.fromCharCode|` +
		`(eval|exec)\s*\(\s*\\x|` +
		`new\s+Function\s*\(\s*['"]\s*\+`)

	rePolyglotPDF       = regexp.MustCompile(`%PDF-`)
	reCommentLine       = regexp.MustCompile(`(?m)^\s*(//|#|;|--|/\*|\*)\s*(.+)$`)
	reSuspiciousPayload = regexp.MustCompile(`^[0-9a-fA-F]{40,}$|^[01]{40,}$`)
	reBase64InComment   = regexp.MustCompile(`^[A-Za-z0-9+/]{60,}={0,2}$`)
)

// padBase64 adds the necessary '=' padding to make s a valid base64 string.
func padBase64(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	}
	return s
}

// ScanShebang checks whether the first line of a file has a suspicious
// shebang (e.g., piping from curl) or a non-standard interpreter path.
func ScanShebang(line string, lineNum int, filePath string) []Finding {
	if lineNum != 1 || !strings.HasPrefix(line, "#!") {
		return nil
	}
	shebang := strings.TrimSpace(line[2:])
	suspicious := []string{
		"curl", "wget", "nc ", "ncat", "netcat",
		"python -c", "python3 -c", "perl -e", "ruby -e",
		"bash -c", "sh -c",
	}
	for _, s := range suspicious {
		if strings.Contains(shebang, s) {
			return []Finding{{
				File: filePath, Line: 1, Col: 1,
				Category: CategoryShebang,
				Detail:   fmt.Sprintf("suspicious shebang: %s", strings.TrimSpace(line)),
			}}
		}
	}
	if !strings.HasPrefix(shebang, "/usr/bin/") &&
		!strings.HasPrefix(shebang, "/bin/") &&
		!strings.HasPrefix(shebang, "/usr/local/bin/") &&
		!strings.HasPrefix(shebang, "/usr/bin/env ") {
		return []Finding{{
			File: filePath, Line: 1, Col: 1,
			Category: CategoryShebang,
			Detail:   fmt.Sprintf("non-standard interpreter path: %s", strings.TrimSpace(line)),
		}}
	}
	return nil
}

// ScanObfuscation detects code obfuscation techniques including base64
// payloads piped to shells, eval with encoded strings, long hex/octal
// escape sequences, and string-concatenation-based eval construction.
func ScanObfuscation(line string, lineNum int, filePath string) []Finding {
	var findings []Finding
	checks := []struct {
		re     *regexp.Regexp
		detail string
	}{
		{reBase64Pipe, "base64-decoded data piped to shell/eval"},
		{reEvalBase64, "eval/exec with base64-encoded payload"},
		{reHexExec, "long hex-encoded byte sequence"},
		{reOctalExec, "long octal-encoded byte sequence"},
		{reEvalConcat, "eval/exec with string concatenation or char-code construction"},
	}
	for _, c := range checks {
		if loc := c.re.FindStringIndex(line); loc != nil {
			findings = append(findings, Finding{
				File: filePath, Line: lineNum, Col: loc[0] + 1,
				Category: CategoryObfuscate,
				Detail:   c.detail,
			})
		}
	}
	if loc := reLongBase64.FindStringIndex(line); loc != nil {
		match := line[loc[0]:loc[1]]
		if _, err := base64.StdEncoding.DecodeString(padBase64(match)); err == nil {
			findings = append(findings, Finding{
				File: filePath, Line: lineNum, Col: loc[0] + 1,
				Category: CategoryObfuscate,
				Detail:   fmt.Sprintf("large base64 blob (%d chars)", len(match)),
			})
		}
	}
	return findings
}

// ScanSteganography looks for encoded data hidden inside source code
// comments, including long hex strings, binary sequences, and base64 blobs.
func ScanSteganography(line string, lineNum int, filePath string) []Finding {
	m := reCommentLine.FindStringSubmatch(line)
	if m == nil {
		return nil
	}
	payload := strings.TrimSpace(m[2])
	if reSuspiciousPayload.MatchString(payload) {
		return []Finding{{
			File: filePath, Line: lineNum, Col: 1,
			Category: CategoryStegano,
			Detail:   fmt.Sprintf("suspicious encoded data in comment (%d chars)", len(payload)),
		}}
	}
	if len(payload) > 60 && reBase64InComment.MatchString(payload) {
		if _, err := base64.StdEncoding.DecodeString(padBase64(payload)); err == nil {
			return []Finding{{
				File: filePath, Line: lineNum, Col: 1,
				Category: CategoryStegano,
				Detail:   fmt.Sprintf("base64-encoded data hidden in comment (%d chars)", len(payload)),
			}}
		}
	}
	return nil
}

// ScanPolyglot checks for files whose magic bytes (ZIP, PDF, ELF, PE)
// don't match their extension, indicating a polyglot file that is valid
// in multiple formats simultaneously.
func ScanPolyglot(data []byte, filePath string) []Finding {
	var findings []Finding
	ext := strings.ToLower(filepath.Ext(filePath))

	if ext != ".zip" && ext != ".jar" && ext != ".war" && ext != ".apk" && ext != ".docx" && ext != ".xlsx" {
		if len(data) >= 4 && data[0] == 'P' && data[1] == 'K' && data[2] == 3 && data[3] == 4 {
			findings = append(findings, Finding{
				File: filePath, Line: 1, Col: 1,
				Category: CategoryPolyglot,
				Detail:   fmt.Sprintf("file has ZIP/JAR magic bytes but %s extension (polyglot)", ext),
			})
		}
	}
	if ext != ".pdf" && len(data) >= 5 {
		if rePolyglotPDF.Match(data[:min(len(data), 1024)]) {
			findings = append(findings, Finding{
				File: filePath, Line: 1, Col: 1,
				Category: CategoryPolyglot,
				Detail:   fmt.Sprintf("file contains %%PDF- header but has %s extension (polyglot)", ext),
			})
		}
	}
	if ext != "" && ext != ".so" && ext != ".o" && ext != ".dylib" {
		if len(data) >= 4 && data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
			findings = append(findings, Finding{
				File: filePath, Line: 1, Col: 1,
				Category: CategoryPolyglot,
				Detail:   fmt.Sprintf("ELF binary masquerading with %s extension", ext),
			})
		}
	}
	if ext != ".exe" && ext != ".dll" && ext != ".sys" {
		if len(data) >= 2 && data[0] == 'M' && data[1] == 'Z' {
			findings = append(findings, Finding{
				File: filePath, Line: 1, Col: 1,
				Category: CategoryPolyglot,
				Detail:   fmt.Sprintf("PE/MZ executable header in %s file (polyglot)", ext),
			})
		}
	}
	return findings
}
