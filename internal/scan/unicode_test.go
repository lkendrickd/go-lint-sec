package scan

import (
	"strings"
	"testing"
)

func TestScanUnicode_BidiChars(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantCat  Category
		wantDesc string
	}{
		{"LTR override", "x = \u202D'admin'", CategoryBidi, "LEFT-TO-RIGHT OVERRIDE"},
		{"RTL override", "x = \u202E'admin'", CategoryBidi, "RIGHT-TO-LEFT OVERRIDE"},
		{"LTR isolate", "x = \u2066'admin'", CategoryBidi, "LEFT-TO-RIGHT ISOLATE"},
		{"RTL isolate", "x = \u2067'admin'", CategoryBidi, "RIGHT-TO-LEFT ISOLATE"},
		{"pop directional", "x = \u202C'admin'", CategoryBidi, "POP DIRECTIONAL FORMATTING"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanUnicode(tt.line, 1, "test.js")
			if len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}
			if findings[0].Category != tt.wantCat {
				t.Errorf("category = %q, want %q", findings[0].Category, tt.wantCat)
			}
			if !strings.Contains(findings[0].Detail, tt.wantDesc) {
				t.Errorf("detail = %q, want substring %q", findings[0].Detail, tt.wantDesc)
			}
		})
	}
}

func TestScanUnicode_InvisibleChars(t *testing.T) {
	tests := []struct {
		name string
		line string
	}{
		{"zero-width space", "pass\u200Bword"},
		{"zero-width joiner", "pass\u200Dword"},
		{"zero-width non-joiner", "pass\u200Cword"},
		{"word joiner", "pass\u2060word"},
		{"soft hyphen", "pass\u00ADword"},
		{"BOM", "pass\uFEFFword"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanUnicode(tt.line, 1, "test.js")
			if len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}
			if findings[0].Category != CategoryInvisible {
				t.Errorf("category = %q, want %q", findings[0].Category, CategoryInvisible)
			}
		})
	}
}

func TestScanUnicode_Homoglyphs(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		lookalike string
	}{
		{"cyrillic a", "v\u0430r x = 1", "'a'"},
		{"cyrillic o", "c\u043Enst x = 1", "'o'"},
		{"cyrillic c", "\u0441onst x = 1", "'c'"},
		{"greek omicron", "\u03BFbject", "'o'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanUnicode(tt.line, 1, "test.js")
			if len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}
			if findings[0].Category != CategoryHomoglyph {
				t.Errorf("category = %q, want %q", findings[0].Category, CategoryHomoglyph)
			}
			if !strings.Contains(findings[0].Detail, tt.lookalike) {
				t.Errorf("detail = %q, want substring %q", findings[0].Detail, tt.lookalike)
			}
		})
	}
}

func TestScanUnicode_TagCharacters(t *testing.T) {
	line := "normal" + string(rune(0xE0001)) + "text"
	findings := ScanUnicode(line, 1, "test.js")
	if len(findings) == 0 {
		t.Fatal("expected tag character finding")
	}
	if findings[0].Category != CategoryTag {
		t.Errorf("category = %q, want %q", findings[0].Category, CategoryTag)
	}
}

func TestScanUnicode_CleanLine(t *testing.T) {
	findings := ScanUnicode("var x = 42; // normal comment", 1, "test.js")
	if len(findings) != 0 {
		t.Errorf("expected no findings for clean line, got %d", len(findings))
	}
}

func TestScanUnicode_ColumnTracking(t *testing.T) {
	findings := ScanUnicode("abcd\u200Befgh", 1, "test.js")
	if len(findings) == 0 {
		t.Fatal("expected finding")
	}
	if findings[0].Col != 5 {
		t.Errorf("col = %d, want 5", findings[0].Col)
	}
}

func TestScanNullBytes(t *testing.T) {
	t.Run("detects null byte", func(t *testing.T) {
		data := []byte("line one\x00more text\n")
		findings := ScanNullBytes(data, "test.txt")
		if len(findings) == 0 {
			t.Fatal("expected null byte finding")
		}
		if findings[0].Category != CategoryNullByte {
			t.Errorf("category = %q, want %q", findings[0].Category, CategoryNullByte)
		}
		if findings[0].Line != 1 {
			t.Errorf("line = %d, want 1", findings[0].Line)
		}
	})

	t.Run("clean file", func(t *testing.T) {
		data := []byte("clean file content\nline two\n")
		findings := ScanNullBytes(data, "test.txt")
		if len(findings) != 0 {
			t.Errorf("expected no findings, got %d", len(findings))
		}
	})

	t.Run("null on second line", func(t *testing.T) {
		data := []byte("line one\nline\x00two\n")
		findings := ScanNullBytes(data, "test.txt")
		if len(findings) == 0 {
			t.Fatal("expected finding")
		}
		if findings[0].Line != 2 {
			t.Errorf("line = %d, want 2", findings[0].Line)
		}
	})
}

func TestScanFilename(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantCat Category
		wantN   int
	}{
		{"double extension exe", "/tmp/readme.txt.exe", CategoryExtension, 1},
		{"double extension sh", "/tmp/data.csv.sh", CategoryExtension, 1},
		{"double extension bat", "/tmp/notes.doc.bat", CategoryExtension, 1},
		{"normal file", "/tmp/main.go", "", 0},
		{"single extension", "/tmp/readme.txt", "", 0},
		{"hidden file ok", "/tmp/.gitignore", "", 0},
		{"RTL override in name", "/tmp/test\u202Eexe.txt", CategoryBidi, 2}, // bidi + non-printable
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanFilename(tt.path)
			if len(findings) != tt.wantN {
				t.Fatalf("findings = %d, want %d", len(findings), tt.wantN)
			}
			if tt.wantN > 0 && findings[0].Category != tt.wantCat {
				t.Errorf("category = %q, want %q", findings[0].Category, tt.wantCat)
			}
		})
	}
}
