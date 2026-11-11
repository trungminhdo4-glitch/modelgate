package scan

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ConfigError marks a config.json that could not be parsed.
type ConfigError struct {
	Err error
}

func (e *ConfigError) Error() string { return "config.json: " + e.Err.Error() }
func (e *ConfigError) Unwrap() error { return e.Err }

// ModelConfig is the subset of a Hugging Face model config that matters for
// supply-chain review. Unknown fields are ignored on purpose.
type ModelConfig struct {
	// TrustRemoteCode is set when the config itself carries the flag.
	TrustRemoteCode *bool `json:"trust_remote_code"`
	// AutoMap maps transformers entry points (e.g. "AutoModel") to the
	// Python file/class that must be downloaded and imported to use them.
	AutoMap map[string]any `json:"auto_map"`
}

// AutoMapEntry is one resolved view of an auto_map value.
type AutoMapEntry struct {
	// Key is the entry point, e.g. "AutoModel".
	Key string `json:"key"`
	// Target is the raw config value.
	Target string `json:"target"`
	// Invalid marks values that are not strings (unexpected config shape).
	Invalid bool `json:"invalid,omitempty"`
}

// ParseConfig parses a model config.json. It only reads data; nothing in the
// config is ever executed or resolved to an import.
func ParseConfig(data []byte) (*ModelConfig, error) {
	cfg := &ModelConfig{}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, &ConfigError{Err: err}
	}
	return cfg, nil
}

// AutoMapEntries returns auto_map entries sorted by key for stable reports.
func (c *ModelConfig) AutoMapEntries() []AutoMapEntry {
	if c == nil || len(c.AutoMap) == 0 {
		return nil
	}
	keys := make([]string, 0, len(c.AutoMap))
	for k := range c.AutoMap {
		keys = append(keys, k)
	}
	sortStrings(keys)
	out := make([]AutoMapEntry, 0, len(keys))
	for _, k := range keys {
		raw := c.AutoMap[k]
		str, ok := raw.(string)
		if !ok {
			out = append(out, AutoMapEntry{Key: k, Invalid: true})
			continue
		}
		out = append(out, AutoMapEntry{Key: k, Target: str})
	}
	return out
}

// sortStrings is a tiny insertion-free wrapper so the package keeps a single
// sorted-strings helper without exporting one.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

var (
	errEmptyTarget   = errors.New("empty auto_map target")
	errUnsafeTarget  = errors.New("unsafe auto_map target")
	segPattern       = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	errInvalidTarget = errors.New("invalid auto_map target")
)

// ResolveAutoMapPath maps an auto_map value to the repository-relative path
// of the Python file that would be imported:
//
//	"modeling.Module" -> "modeling.py"
//	"pkg.sub.Module"  -> "pkg/sub.py"
//	"module.py:Class" -> "module.py"
//	"./module.py"     -> "module.py"
//
// Path traversal ("../"), absolute paths and NUL bytes are rejected so a
// hostile config can never steer the fetcher outside the repository.
func ResolveAutoMapPath(target string) (string, error) {
	t := strings.TrimSpace(target)
	if t == "" {
		return "", errEmptyTarget
	}
	if idx := strings.IndexByte(t, ':'); idx >= 0 {
		t = t[:idx]
	}
	t = strings.TrimPrefix(t, "./")
	t = strings.ReplaceAll(t, `\`, "/")
	if t == "" {
		return "", errEmptyTarget
	}
	if strings.HasPrefix(t, "/") || strings.Contains(t, "..") || strings.ContainsRune(t, 0) {
		return "", fmt.Errorf("%w: %q", errUnsafeTarget, target)
	}
	if !strings.HasSuffix(t, ".py") {
		parts := strings.Split(t, ".")
		// Validate every dot segment — module path pieces and the trailing
		// class name — before joining. The class name never reaches the
		// path-segment check below, so "a. b" must not slip through.
		for _, p := range parts {
			for _, seg := range strings.Split(p, "/") {
				if !segPattern.MatchString(seg) {
					return "", fmt.Errorf("%w: %q", errInvalidTarget, target)
				}
			}
		}
		if len(parts) == 1 {
			t = parts[0] + ".py"
		} else {
			// Last component is the class name, the rest is the module path.
			t = strings.Join(parts[:len(parts)-1], "/") + ".py"
		}
	}
	t = strings.TrimSuffix(t, ".py")
	for _, seg := range strings.Split(t, "/") {
		if !segPattern.MatchString(seg) {
			return "", fmt.Errorf("%w: %q", errInvalidTarget, target)
		}
	}
	return t + ".py", nil
}
