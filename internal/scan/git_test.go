package scan

import (
	"os"
	"os/exec"
	"strings"
	"path/filepath"
	"testing"
)

func TestScanGitAnomalies(t *testing.T) {
	// Create a temporary git repo for testing
	tmpDir := t.TempDir()
	repoDir := filepath.Join(tmpDir, "repo")
	if err := os.MkdirAll(repoDir, 0o755); err != nil {
		t.Fatal(err)
	}

	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", repoDir}, args...)...)
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	git("init")

	t.Run("detects date skew", func(t *testing.T) {
		// Create a commit with >7 day skew between author and committer dates
		cmd := exec.Command("git", "-C", repoDir, "commit", "--allow-empty", "-m", "suspicious commit")
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test.com",
			"GIT_AUTHOR_DATE=2025-01-01T12:00:00",
			"GIT_COMMITTER_DATE=2025-03-15T12:00:00",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("commit failed: %v\n%s", err, out)
		}

		findings, err := ScanGitAnomalies(repoDir)
		if err != nil {
			t.Fatal(err)
		}
		if len(findings) == 0 {
			t.Fatal("expected date skew finding")
		}
		if findings[0].Category != CategoryGitAnomaly {
			t.Errorf("category = %q, want %q", findings[0].Category, CategoryGitAnomaly)
		}
	})

	t.Run("ignores normal commits", func(t *testing.T) {
		// Create a normal commit (same author/committer date)
		cmd := exec.Command("git", "-C", repoDir, "commit", "--allow-empty", "-m", "normal commit")
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test",
			"GIT_AUTHOR_EMAIL=test@test.com",
			"GIT_COMMITTER_NAME=test",
			"GIT_COMMITTER_EMAIL=test@test.com",
			"GIT_AUTHOR_DATE=2025-06-01T12:00:00",
			"GIT_COMMITTER_DATE=2025-06-01T12:00:00",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("commit failed: %v\n%s", err, out)
		}

		findings, err := ScanGitAnomalies(repoDir)
		if err != nil {
			t.Fatal(err)
		}
		// Should still have 1 finding from the previous skewed commit,
		// but the normal commit should not generate one
		normalFound := false
		for _, f := range findings {
			if strings.Contains(f.Detail, "normal commit") {
				normalFound = true
			}
		}
		if normalFound {
			t.Error("normal commit should not be flagged")
		}
	})

	t.Run("not a git repo", func(t *testing.T) {
		notRepo := t.TempDir()
		findings, err := ScanGitAnomalies(notRepo)
		if err != nil {
			t.Errorf("expected nil error for non-repo, got %v", err)
		}
		if findings != nil {
			t.Errorf("expected nil findings for non-repo, got %d", len(findings))
		}
	})
}
