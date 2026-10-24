package policy

import (
	"sync"
	"time"
)

type cacheEntry struct {
	decision  *PolicyDecision
	expiresAt time.Time
}

// DecisionCache provides a high-throughput, thread-safe cache for policy evaluation results.
type DecisionCache struct {
	entries sync.Map
	ttl     time.Duration
}

// NewDecisionCache initializes an in-memory cache with specified TTL.
func NewDecisionCache(ttl time.Duration) *DecisionCache {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &DecisionCache{
		ttl: ttl,
	}
}

// Get retrieves a cached policy verdict by its 64-bit FNV-1a hash key.
func (c *DecisionCache) Get(key uint64) (*PolicyDecision, bool) {
	val, ok := c.entries.Load(key)
	if !ok {
		return nil, false
	}

	entry, ok := val.(cacheEntry)
	if !ok {
		c.entries.Delete(key)
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		c.entries.Delete(key)
		return nil, false
	}

	// Return a copy with CacheHit=true to avoid race on field mutations
	cachedDecision := *entry.decision
	cachedDecision.CacheHit = true
	return &cachedDecision, true
}

// Set stores a policy verdict associated with the 64-bit hash key.
func (c *DecisionCache) Set(key uint64, decision *PolicyDecision) {
	if decision == nil {
		return
	}
	c.entries.Store(key, cacheEntry{
		decision:  decision,
		expiresAt: time.Now().Add(c.ttl),
	})
}

// Purge invalidates all cached decisions (e.g., during zero-downtime policy reloads).
func (c *DecisionCache) Purge() {
	c.entries.Range(func(key, _ any) bool {
		c.entries.Delete(key)
		return true
	})
}
