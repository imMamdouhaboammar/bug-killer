package deepsec

import "time"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHighBug  Severity = "HIGH_BUG"
	SeverityBug      Severity = "BUG"
	SeverityLow      Severity = "LOW"
)

type FileStatus string

const (
	FileStatusPending    FileStatus = "pending"
	FileStatusProcessing FileStatus = "processing"
	FileStatusAnalyzed   FileStatus = "analyzed"
	FileStatusError      FileStatus = "error"
)

type ProjectConfig struct {
	ProjectID string `json:"project_id"`
	RootPath  string `json:"root_path"`
	CreatedAt string `json:"created_at"`
	GithubURL string `json:"github_url,omitempty"`
}

type CandidateMatch struct {
	VulnSlug       string `json:"vuln_slug"`
	LineNumbers    []int  `json:"line_numbers"`
	Snippet        string `json:"snippet"`
	MatchedPattern string `json:"matched_pattern"`
}

type Finding struct {
	FindingID      string   `json:"finding_id"`
	Severity       Severity `json:"severity"`
	VulnSlug       string   `json:"vuln_slug"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	LineNumbers    []int    `json:"line_numbers"`
	Recommendation string   `json:"recommendation"`
	Confidence     string   `json:"confidence"`
	Verdict        string   `json:"verdict,omitempty"`
}

type AnalysisEntry struct {
	RunID          string    `json:"run_id"`
	InvestigatedAt time.Time `json:"investigated_at"`
	DurationMs     int64     `json:"duration_ms"`
	AgentType      string    `json:"agent_type"`
	Model          string    `json:"model"`
	FindingCount   int       `json:"finding_count"`
	CostUSD        float64   `json:"cost_usd,omitempty"`
}

type FileRecord struct {
	FilePath          string           `json:"file_path"`
	ProjectID         string           `json:"project_id"`
	Candidates        []CandidateMatch `json:"candidates"`
	LastScannedAt     string           `json:"last_scanned_at"`
	LastScannedRunID  string           `json:"last_scanned_run_id"`
	FileHash          string           `json:"file_hash"`
	Findings          []Finding        `json:"findings"`
	AnalysisHistory   []AnalysisEntry  `json:"analysis_history"`
	Status            FileStatus       `json:"status"`
	LockedByRunID     string           `json:"locked_by_run_id,omitempty"`
	LockedAt          string           `json:"locked_at,omitempty"`
}

type RunStats struct {
	FilesScanned    int     `json:"files_scanned"`
	CandidatesFound int     `json:"candidates_found"`
	FilesProcessed  int     `json:"files_processed"`
	FindingsCount   int     `json:"findings_count"`
	TotalCostUSD    float64 `json:"total_cost_usd"`
	TotalDurationMs int64   `json:"total_duration_ms"`
}

type RunMeta struct {
	RunID       string    `json:"run_id"`
	ProjectID   string    `json:"project_id"`
	RootPath    string    `json:"root_path"`
	CreatedAt   string    `json:"created_at"`
	CompletedAt string    `json:"completed_at,omitempty"`
	RunType     string    `json:"run_type"`
	Phase       string    `json:"phase"`
	PID         int       `json:"pid"`
	Hostname    string    `json:"hostname"`
	Stats       RunStats  `json:"stats"`
}
