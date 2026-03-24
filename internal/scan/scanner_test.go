package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFile_AllScanners(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.js")
	content := "var pass\u200Bword = 'secret';\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	checks := map[string]bool{}
	for _, name := range AllScannerNames() {
		checks[name] = true
	}

	findings, err := File(path, checks)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Category == CategoryInvisible {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected invisible character finding with all checks enabled")
	}
}

func TestFile_SelectiveScanner(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.js")
	content := "#!/opt/evil/bin/python\nvar pass\u200Bword = 'secret';\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := File(path, map[string]bool{"unicode": true})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.Category == CategoryShebang {
			t.Error("shebang scanner should not run when only unicode is enabled")
		}
	}
	found := false
	for _, f := range findings {
		if f.Category == CategoryInvisible {
			found = true
		}
	}
	if !found {
		t.Error("expected invisible character finding")
	}
}

func TestFile_Unreadable(t *testing.T) {
	findings, err := File("/nonexistent/path/file.js", map[string]bool{"unicode": true})
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
	_ = findings
}

func TestFile_NullByteDetection(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.txt")
	// File with a single null byte should NOT be classified as binary,
	// and the null-byte scanner should detect it.
	content := []byte("line one\x00more text\nline two\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}

	findings, err := File(path, map[string]bool{"null-byte": true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range findings {
		if f.Category == CategoryNullByte {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected null-byte finding for file with single null byte")
	}
}

func TestCollectFiles(t *testing.T) {
	tmpDir := t.TempDir()

	files := map[string]string{
		"main.go":             "package main",
		"utils.py":            "# python",
		"readme.txt":          "hello",
		"image.png":           "fake png",
		"sub/nested.js":       "var x = 1",
		".git/config":         "should be skipped",
		"node_modules/lib.js": "should be skipped",
		"vendor/dep.go":       "should be skipped",
	}
	for name, content := range files {
		path := filepath.Join(tmpDir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	collected := CollectFiles([]string{tmpDir}, CodeExtensions)

	nameSet := make(map[string]bool)
	for _, f := range collected {
		nameSet[filepath.Base(f)] = true
	}

	want := []string{"main.go", "utils.py", "readme.txt", "nested.js"}
	for _, w := range want {
		if !nameSet[w] {
			t.Errorf("expected %q to be collected", w)
		}
	}

	skip := []string{"image.png", "config", "lib.js", "dep.go"}
	for _, s := range skip {
		if nameSet[s] {
			t.Errorf("expected %q to be skipped", s)
		}
	}
}

func TestCollectFiles_SingleFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "standalone.xyz")
	if err := os.WriteFile(path, []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}

	collected := CollectFiles([]string{path}, CodeExtensions)
	if len(collected) != 1 {
		t.Fatalf("expected 1 file, got %d", len(collected))
	}
	if collected[0] != path {
		t.Errorf("got %q, want %q", collected[0], path)
	}
}

func TestCollectFiles_NonexistentPath(t *testing.T) {
	collected := CollectFiles([]string{"/nonexistent/path"}, CodeExtensions)
	if len(collected) != 0 {
		t.Errorf("expected 0 files, got %d", len(collected))
	}
}

func TestIsBinaryFile(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"normal text", []byte("hello world\n"), false},
		{"binary heavy", []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x01, 0x02}, true},
		{"empty", []byte{}, false},
		{"single null in text", []byte("hello\x00world, this is mostly text content"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBinaryFile(tt.data); got != tt.want {
				t.Errorf("isBinaryFile() = %v, want %v", got, tt.want)
			}
		})
	}
}
