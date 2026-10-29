package deepsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/spf13/afero"
)

var defaultIgnorePatterns = []string{
	"node_modules",
	".git",
	".deepsec",
	"dist",
	"build",
	"target",
	".next",
	"coverage",
	"fixtures",
	"__tests__",
}

var safeProjectID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

func validateProjectID(projectID string) error {
	if !safeProjectID.MatchString(projectID) {
		return fmt.Errorf("invalid project ID: expected 1-128 letters, digits, underscores or hyphens, beginning with a letter or digit")
	}
	return nil
}

type Runner struct {
	fs afero.Fs
}

func NewRunner(fs afero.Fs) *Runner {
	if fs == nil {
		fs = afero.NewOsFs()
	}
	return &Runner{fs: fs}
}

func (r *Runner) dataDir(projectID string) string {
	return filepath.Join(".deepsec", "data", projectID)
}

func (r *Runner) filesDir(projectID string) string {
	return filepath.Join(r.dataDir(projectID), "files")
}

func (r *Runner) runsDir(projectID string) string {
	return filepath.Join(r.dataDir(projectID), "runs")
}

func (r *Runner) EnsureProject(projectID, rootPath string) error {
	if err := validateProjectID(projectID); err != nil {
		return err
	}
	pDir := r.dataDir(projectID)
	if err := r.fs.MkdirAll(r.filesDir(projectID), 0755); err != nil {
		return err
	}
	if err := r.fs.MkdirAll(r.runsDir(projectID), 0755); err != nil {
		return err
	}

	configPath := filepath.Join(pDir, "project.json")
	exists, err := afero.Exists(r.fs, configPath)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	config := ProjectConfig{
		ProjectID: projectID,
		RootPath:  rootPath,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	bytes, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return afero.WriteFile(r.fs, configPath, bytes, 0644)
}

func isIgnored(path string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for _, part := range parts {
		for _, ignore := range defaultIgnorePatterns {
			if part == ignore {
				return true
			}
		}
	}
	ext := filepath.Ext(path)
	if ext == ".md" || ext == ".lock" || ext == ".png" || ext == ".jpg" {
		return true
	}
	return false
}

func (r *Runner) Scan(ctx context.Context, rootPath, projectID string) (*RunStats, error) {
	if err := r.EnsureProject(projectID, rootPath); err != nil {
		return nil, err
	}

	runID := fmt.Sprintf("scan-%s-%04x", time.Now().UTC().Format("20060102150405"), time.Now().UnixNano()%0xffff)
	stats := &RunStats{}

	sqlRegex := regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*(\+|\$|\$\{)`)
	rceRegex := regexp.MustCompile(`(?i)\b(exec|execSync|spawn|spawnSync|subprocess\.call|eval)\s*\(`)
	secretRegex := regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9_]{36}|BEGIN (RSA|EC|PRIVATE) KEY)`)

	err := afero.Walk(r.fs, rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		rel, err := filepath.Rel(rootPath, path)
		if err != nil || isIgnored(rel) {
			return nil
		}

		data, err := afero.ReadFile(r.fs, path)
		if err != nil {
			return nil
		}

		stats.FilesScanned++
		lines := strings.Split(string(data), "\n")
		var candidates []CandidateMatch

		for idx, line := range lines {
			lineNo := idx + 1
			if sqlRegex.MatchString(line) {
				candidates = append(candidates, CandidateMatch{
					VulnSlug:       "sql-injection",
					LineNumbers:    []int{lineNo},
					Snippet:        line,
					MatchedPattern: "SQL Raw Concatenation",
				})
			}
			if rceRegex.MatchString(line) {
				candidates = append(candidates, CandidateMatch{
					VulnSlug:       "rce",
					LineNumbers:    []int{lineNo},
					Snippet:        line,
					MatchedPattern: "Command Execution",
				})
			}
			if secretRegex.MatchString(line) {
				candidates = append(candidates, CandidateMatch{
					VulnSlug:       "secrets-exposure",
					LineNumbers:    []int{lineNo},
					Snippet:        line,
					MatchedPattern: "Hardcoded Secret",
				})
			}
		}

		if len(candidates) > 0 {
			stats.CandidatesFound += len(candidates)
			h := sha256.Sum256(data)
			fileHash := hex.EncodeToString(h[:])

			record := FileRecord{
				FilePath:         rel,
				ProjectID:        projectID,
				Candidates:       candidates,
				LastScannedAt:    time.Now().UTC().Format(time.RFC3339),
				LastScannedRunID: runID,
				FileHash:         fileHash,
				Status:           FileStatusPending,
			}

			recordPath := filepath.Join(r.filesDir(projectID), rel+".json")
			if err := r.fs.MkdirAll(filepath.Dir(recordPath), 0755); err != nil {
				return err
			}
			recBytes, err := json.MarshalIndent(record, "", "  ")
			if err != nil {
				return err
			}
			if err := afero.WriteFile(r.fs, recordPath, recBytes, 0644); err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return stats, nil
}

func (r *Runner) LoadPendingFiles(projectID string) ([]FileRecord, error) {
	if err := validateProjectID(projectID); err != nil {
		return nil, err
	}
	filesDir := r.filesDir(projectID)
	var pending []FileRecord

	exists, err := afero.Exists(r.fs, filesDir)
	if err != nil || !exists {
		return nil, err
	}

	err = afero.Walk(r.fs, filesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() || filepath.Ext(path) != ".json" {
			return nil
		}
		data, err := afero.ReadFile(r.fs, path)
		if err != nil {
			return nil
		}
		var rec FileRecord
		if err := json.Unmarshal(data, &rec); err == nil {
			if rec.Status == FileStatusPending {
				pending = append(pending, rec)
			}
		}
		return nil
	})

	return pending, err
}

func (r *Runner) Process(ctx context.Context, rootPath, projectID string, concurrency, batchSize int) (*RunStats, error) {
	if concurrency < 1 {
		concurrency = 1
	}
	if batchSize < 1 {
		batchSize = 5
	}

	pending, err := r.LoadPendingFiles(projectID)
	if err != nil {
		return nil, err
	}

	runID := fmt.Sprintf("proc-%s", time.Now().UTC().Format("20060102150405"))
	stats := &RunStats{}
	start := time.Now()

	batches := make([][]FileRecord, 0)
	for i := 0; i < len(pending); i += batchSize {
		end := i + batchSize
		if end > len(pending) {
			end = len(pending)
		}
		batches = append(batches, pending[i:end])
	}

	batchChan := make(chan []FileRecord, len(batches))
	for _, b := range batches {
		batchChan <- b
	}
	close(batchChan)

	var wg sync.WaitGroup
	var mu sync.Mutex
	workerErrors := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for batch := range batchChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				for _, rec := range batch {
					fileStart := time.Now()
					// This is deterministic pattern classification, not an AI investigation
					// or a verified exploit. Preserve that distinction in every record.
					findings := make([]Finding, 0)
					for _, c := range rec.Candidates {
						h := sha256.Sum256([]byte(projectID + ":" + rec.FilePath + ":" + c.VulnSlug))
						fid := fmt.Sprintf("finding_%s", hex.EncodeToString(h[:])[:16])

						findings = append(findings, Finding{
							FindingID:      fid,
							Severity:       SeverityMedium,
							VulnSlug:       c.VulnSlug,
							Title:          fmt.Sprintf("Unverified pattern indicator in %s", rec.FilePath),
							Description:    c.Snippet,
							LineNumbers:    c.LineNumbers,
							Recommendation: "Review the flagged code path and validate exploitability before remediation",
							Confidence:     "low",
						})
					}

					rec.Findings = findings
					rec.Status = FileStatusAnalyzed
					rec.AnalysisHistory = append(rec.AnalysisHistory, AnalysisEntry{
						RunID:          runID,
						InvestigatedAt: time.Now().UTC(),
						DurationMs:     time.Since(fileStart).Milliseconds(),
						AgentType:      "local-patterns",
						Model:          "deterministic-pattern-matcher-v1",
						FindingCount:   len(findings),
						CostUSD:        0,
					})

					recordPath := filepath.Join(r.filesDir(projectID), rec.FilePath+".json")
					recBytes, err := json.MarshalIndent(rec, "", "  ")
					if err != nil {
						workerErrors <- fmt.Errorf("marshal file record %s: %w", rec.FilePath, err)
						return
					}
					if err := afero.WriteFile(r.fs, recordPath, recBytes, 0644); err != nil {
						workerErrors <- fmt.Errorf("write file record %s: %w", rec.FilePath, err)
						return
					}

					mu.Lock()
					stats.FilesProcessed++
					stats.FindingsCount += len(findings)
					mu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	close(workerErrors)
	for err := range workerErrors {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	stats.TotalDurationMs = time.Since(start).Milliseconds()
	return stats, nil
}
