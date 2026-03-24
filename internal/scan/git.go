package scan

import (
	"bufio"
	"context"
	"fmt"
	"math"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// gitTimeout is the maximum time allowed for git commands.
const gitTimeout = 30 * time.Second

// ScanGitAnomalies inspects the last 100 commits in a git repository for
// author-vs-committer date skew greater than 7 days. Large skew indicates
// a force-push or rebase that rewrote commit history, a technique used in
// supply-chain attacks to inject malicious commits disguised as old changes.
// Returns nil, nil if the path is not inside a git repository.
func ScanGitAnomalies(repoPath string) ([]Finding, error) {
	ctx, cancel := context.WithTimeout(context.Background(), gitTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "-C", repoPath, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return nil, nil
	}
	gitRoot := strings.TrimSpace(string(out))

	cmd = exec.CommandContext(ctx, "git", "-C", gitRoot, "log", "--format=%H|%at|%ct|%s", "-100")
	out, err = cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git log failed: %w", err)
	}

	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "|", 4)
		if len(parts) < 4 {
			continue
		}
		hash := parts[0]
		if len(hash) > 12 {
			hash = hash[:12]
		}
		authorTS, err1 := strconv.ParseInt(parts[1], 10, 64)
		committerTS, err2 := strconv.ParseInt(parts[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}

		diff := committerTS - authorTS
		daysDiff := math.Abs(float64(diff)) / 86400.0
		if daysDiff > 7 {
			authorTime := time.Unix(authorTS, 0).Format("2006-01-02")
			committerTime := time.Unix(committerTS, 0).Format("2006-01-02")
			findings = append(findings, Finding{
				File: gitRoot,
				Category: CategoryGitAnomaly,
				Detail: fmt.Sprintf("commit %s: author date %s vs committer date %s (%.0f day skew) — %s",
					hash, authorTime, committerTime, daysDiff, parts[3]),
			})
		}
	}

	return findings, nil
}
