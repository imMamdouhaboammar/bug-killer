package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// EvaluatorConfig configures the embedded OPA evaluation manager.
type EvaluatorConfig struct {
	RulePaths      []string
	RawRuleModules map[string]string
	CacheTTL       time.Duration
	QueryPath      string // Default: "data.omni.runtime.decision"
}

// PolicyEvaluator manages pre-compiled Rego policies and thread-safe inline evaluations.
type PolicyEvaluator struct {
	mu           sync.RWMutex
	compiler     *ast.Compiler
	prepared     rego.PreparedEvalQuery
	cache        *DecisionCache
	queryPath    string
	rulePaths    []string
	rawModules   map[string]string
	lastModified map[string]time.Time
}

// NewPolicyEvaluator compiles Rego modules and initializes the embedded execution engine.
func NewPolicyEvaluator(ctx context.Context, cfg EvaluatorConfig) (*PolicyEvaluator, error) {
	if cfg.QueryPath == "" {
		cfg.QueryPath = "data.omni.runtime.decision"
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 30 * time.Second
	}

	pe := &PolicyEvaluator{
		cache:        NewDecisionCache(cfg.CacheTTL),
		queryPath:    cfg.QueryPath,
		rulePaths:    cfg.RulePaths,
		rawModules:   cfg.RawRuleModules,
		lastModified: make(map[string]time.Time),
	}

	if err := pe.compileAndPrepare(ctx); err != nil {
		return nil, fmt.Errorf("failed to initialize embedded OPA evaluator: %w", err)
	}

	return pe, nil
}

// compileAndPrepare parses, compiles, and prepares the Rego query in memory.
func (pe *PolicyEvaluator) compileAndPrepare(ctx context.Context) error {
	modules := make(map[string]string)

	// 1. Ingest raw in-memory modules
	for name, content := range pe.rawModules {
		modules[name] = content
	}

	// 2. Ingest disk files
	for _, path := range pe.rulePaths {
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("failed to stat rego rule path %s: %w", path, err)
		}

		if info.IsDir() {
			entries, err := os.ReadDir(path)
			if err != nil {
				return fmt.Errorf("failed to read rego rule directory %s: %w", path, err)
			}
			for _, entry := range entries {
				if !entry.IsDir() && filepath.Ext(entry.Name()) == ".rego" {
					filePath := filepath.Join(path, entry.Name())
					data, err := os.ReadFile(filePath)
					if err != nil {
						return fmt.Errorf("failed to read %s: %w", filePath, err)
					}
					modules[filePath] = string(data)
					if fi, err := entry.Info(); err == nil {
						pe.lastModified[filePath] = fi.ModTime()
					}
				}
			}
		} else {
			data, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read %s: %w", path, err)
			}
			modules[path] = string(data)
			pe.lastModified[path] = info.ModTime()
		}
	}

	if len(modules) == 0 {
		return fmt.Errorf("no Rego policy modules supplied to evaluator")
	}

	// 3. Compile AST with strict validation
	compiler := ast.NewCompiler()
	parsedModules := make(map[string]*ast.Module, len(modules))

	for filename, content := range modules {
		mod, err := ast.ParseModule(filename, content)
		if err != nil {
			return fmt.Errorf("rego parse error in %s: %w", filename, err)
		}
		parsedModules[filename] = mod
	}

	compiler.Compile(parsedModules)
	if compiler.Failed() {
		return fmt.Errorf("rego compilation errors: %v", compiler.Errors)
	}

	// 4. Pre-compile the evaluation query
	r := rego.New(
		rego.Query(pe.queryPath),
		rego.Compiler(compiler),
	)

	prepared, err := r.PrepareForEval(ctx)
	if err != nil {
		return fmt.Errorf("failed to prepare rego query '%s': %w", pe.queryPath, err)
	}

	pe.compiler = compiler
	pe.prepared = prepared
	return nil
}

// Reload re-compiles policy definitions atomically without interrupting active readers.
func (pe *PolicyEvaluator) Reload(ctx context.Context) error {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	if err := pe.compileAndPrepare(ctx); err != nil {
		return fmt.Errorf("hot-reload aborted due to compilation error: %w", err)
	}

	// Purge stale cache entries upon rule changes
	pe.cache.Purge()
	return nil
}

// EvaluateNetwork runs high-frequency packet telemetry against pre-compiled rules.
func (pe *PolicyEvaluator) EvaluateNetwork(ctx context.Context, input *NetworkInput) (*PolicyDecision, error) {
	if input == nil {
		return nil, fmt.Errorf("network input cannot be nil")
	}

	// 1. Check ultra-fast cache
	cacheKey := input.HashKey()
	if cached, ok := pe.cache.Get(cacheKey); ok {
		return cached, nil
	}

	// 2. Read lock for prepared query evaluation
	pe.mu.RLock()
	prepared := pe.prepared
	pe.mu.RUnlock()

	evalInput := map[string]any{
		"network": input,
	}

	results, err := prepared.Eval(ctx, rego.EvalInput(evalInput))
	if err != nil {
		return nil, fmt.Errorf("rego network evaluation error: %w", err)
	}

	dec, err := pe.parseDecision(results)
	if err != nil {
		return nil, err
	}

	// Cache decision if valid
	pe.cache.Set(cacheKey, dec)
	return dec, nil
}

// EvaluateProcess runs kernel/process telemetry against pre-compiled rules.
func (pe *PolicyEvaluator) EvaluateProcess(ctx context.Context, input *ProcessInput) (*PolicyDecision, error) {
	if input == nil {
		return nil, fmt.Errorf("process input cannot be nil")
	}

	// 1. Check ultra-fast cache
	cacheKey := input.HashKey()
	if cached, ok := pe.cache.Get(cacheKey); ok {
		return cached, nil
	}

	// 2. Read lock for prepared query evaluation
	pe.mu.RLock()
	prepared := pe.prepared
	pe.mu.RUnlock()

	evalInput := map[string]any{
		"process": input,
	}

	results, err := prepared.Eval(ctx, rego.EvalInput(evalInput))
	if err != nil {
		return nil, fmt.Errorf("rego process evaluation error: %w", err)
	}

	dec, err := pe.parseDecision(results)
	if err != nil {
		return nil, err
	}

	// Cache decision if valid
	pe.cache.Set(cacheKey, dec)
	return dec, nil
}

// parseDecision unpacks the OPA resultSet into the typed PolicyDecision model.
func (pe *PolicyEvaluator) parseDecision(results rego.ResultSet) (*PolicyDecision, error) {
	if len(results) == 0 || len(results[0].Expressions) == 0 {
		return &PolicyDecision{
			Allow:       true,
			Action:      "ALLOW",
			Severity:    "LOW",
			EvaluatedAt: time.Now(),
		}, nil
	}

	val := results[0].Expressions[0].Value
	data, err := json.Marshal(val)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal rego decision value: %w", err)
	}

	var dec PolicyDecision
	if err := json.Unmarshal(data, &dec); err != nil {
		return nil, fmt.Errorf("failed to unmarshal rego decision into schema: %w", err)
	}

	dec.EvaluatedAt = time.Now()
	dec.RuleCount = len(dec.Violations)
	return &dec, nil
}

// StartWatcher spawns a background filesystem watcher executing zero-downtime hot reloading.
func (pe *PolicyEvaluator) StartWatcher(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 2 * time.Second
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if pe.hasChanges() {
					_ = pe.Reload(ctx)
				}
			}
		}
	}()
}

func (pe *PolicyEvaluator) hasChanges() bool {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	for filePath, lastMtime := range pe.lastModified {
		fi, err := os.Stat(filePath)
		if err != nil {
			continue
		}
		if fi.ModTime().After(lastMtime) {
			return true
		}
	}
	return false
}
