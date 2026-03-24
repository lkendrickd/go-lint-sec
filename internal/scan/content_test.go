package scan

import (
	"strings"
	"testing"
)

func TestScanShebang(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		lineNum int
		wantN   int
	}{
		{"curl shebang", "#!/usr/bin/env curl | bash", 1, 1},
		{"wget shebang", "#!/usr/bin/env wget -O - | sh", 1, 1},
		{"python -c shebang", "#!/usr/bin/env python -c", 1, 1},
		{"netcat shebang", "#!/usr/bin/env ncat", 1, 1},
		{"normal python shebang", "#!/usr/bin/env python3", 1, 0},
		{"normal bash shebang", "#!/bin/bash", 1, 0},
		{"normal sh shebang", "#!/bin/sh", 1, 0},
		{"usr local", "#!/usr/local/bin/node", 1, 0},
		{"non-standard path", "#!/opt/custom/bin/ruby", 1, 1},
		{"not first line", "#!/bin/bash", 2, 0},
		{"not a shebang", "echo hello", 1, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanShebang(tt.line, tt.lineNum, "test.sh")
			if len(findings) != tt.wantN {
				t.Errorf("findings = %d, want %d", len(findings), tt.wantN)
			}
			if tt.wantN > 0 && findings[0].Category != CategoryShebang {
				t.Errorf("category = %q, want %q", findings[0].Category, CategoryShebang)
			}
		})
	}
}

func TestScanObfuscation(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantN   int
		wantSub string
	}{
		{
			"base64 pipe to bash",
			`echo aGVsbG8= | base64 --decode | bash`,
			1, "base64-decoded data piped to shell",
		},
		{
			"base64 pipe to sh",
			`cat payload.txt | base64 -d | sh`,
			1, "base64-decoded data piped to shell",
		},
		{
			"eval with atob",
			`eval(atob("ZG9jdW1lbnQ="))`,
			1, "eval/exec with base64-encoded payload",
		},
		{
			"long hex sequence",
			`var s = "\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64"`,
			1, "long hex-encoded byte sequence",
		},
		{
			"long octal sequence",
			`var s = "\110\145\154\154\157\040\127\157\162\154\144"`,
			1, "long octal-encoded byte sequence",
		},
		{
			"eval with chr construction",
			`eval(chr(72) + chr(101))`,
			1, "eval/exec with string concatenation",
		},
		{
			"eval with fromCharCode",
			`eval(String.fromCharCode(72,101,108))`,
			1, "eval/exec with string concatenation",
		},
		{
			"new Function with string concat",
			`new Function( ' + code + ')`,
			1, "eval/exec with string concatenation",
		},
		{
			"clean code",
			`var x = 42;`,
			0, "",
		},
		{
			"short base64 ok",
			`var token = "aGVsbG8=";`,
			0, "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanObfuscation(tt.line, 1, "test.js")
			if len(findings) != tt.wantN {
				t.Fatalf("findings = %d, want %d; findings: %v", len(findings), tt.wantN, findings)
			}
			if tt.wantN > 0 && !strings.Contains(findings[0].Detail, tt.wantSub) {
				t.Errorf("detail = %q, want substring %q", findings[0].Detail, tt.wantSub)
			}
		})
	}
}

func TestScanObfuscation_LargeBase64(t *testing.T) {
	blob := strings.Repeat("QUFB", 30)
	line := `var data = "` + blob + `"`
	findings := ScanObfuscation(line, 1, "test.js")
	found := false
	for _, f := range findings {
		if strings.Contains(f.Detail, "large base64 blob") {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected large base64 blob finding")
	}
}

func TestScanSteganography(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		wantN int
	}{
		{"long hex in comment", "// 48656c6c6f20576f726c642048656c6c6f20576f726c6448656c6c6f", 1},
		{"long binary in comment", "# 0101010101010101010101010101010101010101010101010101", 1},
		{"normal comment", "// this is a normal comment", 0},
		{"short hex comment", "// abc123", 0},
		{"not a comment", "var x = 48656c6c6f;", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanSteganography(tt.line, 1, "test.js")
			if len(findings) != tt.wantN {
				t.Errorf("findings = %d, want %d", len(findings), tt.wantN)
			}
			if tt.wantN > 0 && findings[0].Category != CategoryStegano {
				t.Errorf("category = %q, want %q", findings[0].Category, CategoryStegano)
			}
		})
	}
}

func TestScanPolyglot(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		path    string
		wantN   int
		wantSub string
	}{
		{
			"ZIP magic in JS file",
			[]byte{'P', 'K', 3, 4, 0, 0, 0, 0},
			"payload.js",
			1, "ZIP/JAR",
		},
		{
			"ZIP magic in JAR file (ok)",
			[]byte{'P', 'K', 3, 4, 0, 0, 0, 0},
			"lib.jar",
			0, "",
		},
		{
			"PDF header in PY file",
			append([]byte("%PDF-1.4 fake header\n"), make([]byte, 1024)...),
			"script.py",
			1, "%PDF-",
		},
		{
			"PDF in PDF file (ok)",
			append([]byte("%PDF-1.4\n"), make([]byte, 1024)...),
			"doc.pdf",
			0, "",
		},
		{
			"ELF in TXT file",
			[]byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0},
			"readme.txt",
			1, "ELF binary",
		},
		{
			"ELF in .so file (ok)",
			[]byte{0x7f, 'E', 'L', 'F', 0, 0, 0, 0},
			"lib.so",
			0, "",
		},
		{
			"PE/MZ in JS file",
			[]byte{'M', 'Z', 0, 0},
			"util.js",
			1, "PE/MZ",
		},
		{
			"PE in EXE file (ok)",
			[]byte{'M', 'Z', 0, 0},
			"app.exe",
			0, "",
		},
		{
			"clean text file",
			[]byte("just normal text content here"),
			"readme.txt",
			0, "",
		},
		{
			"empty file no panic",
			[]byte{},
			"empty.js",
			0, "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanPolyglot(tt.data, tt.path)
			if len(findings) != tt.wantN {
				t.Fatalf("findings = %d, want %d", len(findings), tt.wantN)
			}
			if tt.wantN > 0 && !strings.Contains(findings[0].Detail, tt.wantSub) {
				t.Errorf("detail = %q, want substring %q", findings[0].Detail, tt.wantSub)
			}
		})
	}
}

func TestPadBase64(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"YQ", "YQ=="},
		{"YWI", "YWI="},
		{"YWJj", "YWJj"},
		{"", ""},
	}
	for _, tt := range tests {
		got := padBase64(tt.in)
		if got != tt.want {
			t.Errorf("padBase64(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
