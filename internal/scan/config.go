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
	// CustomPipelines maps a pipeline task to its definition; the "impl"
	// class is imported by pipeline(..., trust_remote_code=True).
	CustomPipelines map[string]any `json:"custom_pipelines"`
}

// PipelineEntries returns one entry per custom_pipelines task, sorted by
// task, keyed "custom_pipelines.<task>". A task without a string "impl" is
// invalid: transformers refuses it, and its code path cannot be resolved.
func (c *ModelConfig) PipelineEntries() []AutoMapEntry {
	if c == nil || len(c.CustomPipelines) == 0 {
		return nil
	}
	tasks := make([]string, 0, len(c.CustomPipelines))
	for task := range c.CustomPipelines {
		tasks = append(tasks, task)
	}
	sortStrings(tasks)
	out := make([]AutoMapEntry, 0, len(tasks))
	for _, task := range tasks {
		key := "custom_pipelines." + task
		def, _ := c.CustomPipelines[task].(map[string]any)
		impl, ok := def["impl"].(string)
		if !ok {
			out = append(out, AutoMapEntry{Key: key, Invalid: true})
			continue
		}
		out = append(out, AutoMapEntry{Key: key, Target: impl})
	}
	return out
}

// entryPoints is every remote-code entry point of one config file:
// auto_map entries followed by custom_pipelines implementations.
func (c *ModelConfig) entryPoints() []AutoMapEntry {
	return append(c.AutoMapEntries(), c.PipelineEntries()...)
}

// entryLabel names an entry in finding messages.
func entryLabel(e AutoMapEntry) string {
	if strings.HasPrefix(e.Key, "custom_pipelines.") {
		return e.Key + ".impl"
	}
	return fmt.Sprintf("auto_map[%q]", e.Key)
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
		switch v := c.AutoMap[k].(type) {
		case string:
			out = append(out, AutoMapEntry{Key: k, Target: v})
		case []any:
			// transformers stores tokenizer classes as a [slow, fast] pair;
			// a null side means "no such class". Every named class is a
			// module that gets imported, so each becomes its own entry.
			for _, el := range v {
				switch s := el.(type) {
				case nil:
				case string:
					out = append(out, AutoMapEntry{Key: k, Target: s})
				default:
					out = append(out, AutoMapEntry{Key: k, Invalid: true})
				}
			}
		default:
			out = append(out, AutoMapEntry{Key: k, Invalid: true})
		}
	}
	return out
}

// RemoteAutoMapRepo reports the repository of a cross-repository auto_map
// reference. transformers splits "org/repo--module.Class" at "--" and loads
// module.py from org/repo, so that code is not part of the scanned repository.
func RemoteAutoMapRepo(target string) (string, bool) {
	repo, _, found := strings.Cut(strings.TrimSpace(target), "--")
	if !found || repo == "" {
		return "", false
	}
	return repo, true
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
