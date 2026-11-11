package scan

import (
	"errors"
	"strings"
	"testing"
)

func TestParseConfigValid(t *testing.T) {
	t.Parallel()
	cfg, err := ParseConfig([]byte(`{"trust_remote_code": true, "auto_map": {"AutoModel": "mod.Cls"}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.TrustRemoteCode == nil || !*cfg.TrustRemoteCode {
		t.Fatal("trust_remote_code not parsed")
	}
	entries := cfg.AutoMapEntries()
	if len(entries) != 1 || entries[0].Target != "mod.Cls" {
		t.Fatalf("entries = %+v", entries)
	}
}

func TestParseConfigInvalid(t *testing.T) {
	t.Parallel()
	_, err := ParseConfig([]byte(`{`))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
	var ce *ConfigError
	if !errors.As(err, &ce) {
		t.Fatalf("expected *ConfigError, got %T", err)
	}
	if !strings.Contains(err.Error(), "config.json:") {
		t.Fatalf("error message should name the file: %v", err)
	}
	if errors.Unwrap(err) == nil {
		t.Fatal("ConfigError must unwrap to the JSON error")
	}
}

func TestAutoMapEntriesSortedAndTyped(t *testing.T) {
	t.Parallel()
	cfg, err := ParseConfig([]byte(`{"auto_map": {"AutoModel": "m.C", "AutoTokenizer": 5, "AutoConfig": "c.C"}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	entries := cfg.AutoMapEntries()
	if len(entries) != 3 {
		t.Fatalf("want 3 entries, got %d", len(entries))
	}
	if entries[0].Key != "AutoConfig" || entries[1].Key != "AutoModel" || entries[2].Key != "AutoTokenizer" {
		t.Fatalf("entries not sorted by key: %+v", entries)
	}
	if !entries[2].Invalid || entries[1].Invalid {
		t.Fatalf("invalid marking wrong: %+v", entries)
	}
}

func TestAutoMapEntriesEmpty(t *testing.T) {
	t.Parallel()
	var cfg *ModelConfig
	if cfg.AutoMapEntries() != nil {
		t.Fatal("nil config must return nil entries")
	}
	cfg2, _ := ParseConfig([]byte(`{}`))
	if cfg2.AutoMapEntries() != nil {
		t.Fatal("config without auto_map must return nil entries")
	}
}

func TestResolveAutoMapPath(t *testing.T) {
	t.Parallel()
	valid := []struct{ in, want string }{
		{"modeling.Fixture", "modeling.py"},
		{"pkg.sub.Mod", "pkg/sub.py"},
		{"module.py:Klass", "module.py"},
		{"./local.py", "local.py"},
		{"plainmodule", "plainmodule.py"},
		{"sub/local_mod.py", "sub/local_mod.py"},
		{"  spaced.Mod  ", "spaced.py"},
	}
	for _, tc := range valid {
		got, err := ResolveAutoMapPath(tc.in)
		if err != nil {
			t.Fatalf("ResolveAutoMapPath(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ResolveAutoMapPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	invalid := []string{"", "   ", "../evil.py", "/etc/passwd", "a\x00b", "sub/../x.Mod", "weird name.Mod", ":", "a. b"}
	for _, in := range invalid {
		if got, err := ResolveAutoMapPath(in); err == nil {
			t.Fatalf("ResolveAutoMapPath(%q) = %q, want error", in, got)
		}
	}
}

func FuzzResolveAutoMapPath(f *testing.F) {
	f.Add("modeling.Module")
	f.Add("../evil.py")
	f.Add("pkg.sub.Class")
	f.Add("")
	f.Fuzz(func(t *testing.T, target string) {
		got, err := ResolveAutoMapPath(target)
		if err != nil {
			return
		}
		if strings.Contains(got, "..") || strings.HasPrefix(got, "/") || strings.ContainsRune(got, 0) {
			t.Fatalf("unsafe path %q accepted for input %q", got, target)
		}
		if !strings.HasSuffix(got, ".py") {
			t.Fatalf("path %q must end in .py", got)
		}
		for _, seg := range strings.Split(strings.TrimSuffix(got, ".py"), "/") {
			if seg == "" {
				t.Fatalf("empty segment in %q", got)
			}
		}
	})
}

func FuzzParseConfig(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"trust_remote_code": true}`))
	f.Add([]byte(`{"auto_map": {"AutoModel": "m.C"}}`))
	f.Add([]byte(`not json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := ParseConfig(data)
		if err != nil {
			return
		}
		entries := cfg.AutoMapEntries()
		// AutoMapEntries must mirror auto_map 1:1 and faithfully: an empty
		// key or empty target is odd input, but it is the config's own data
		// and is reported as-is (downstream rules handle the consequences).
		if len(entries) != len(cfg.AutoMap) {
			t.Fatalf("%d entries for %d auto_map keys", len(entries), len(cfg.AutoMap))
		}
		byKey := make(map[string]AutoMapEntry, len(entries))
		for _, e := range entries {
			byKey[e.Key] = e
		}
		for k, raw := range cfg.AutoMap {
			e, ok := byKey[k]
			if !ok {
				t.Fatalf("missing entry for key %q", k)
			}
			if s, isString := raw.(string); isString {
				if e.Invalid {
					t.Fatalf("entry %q wrongly marked invalid", k)
				}
				if e.Target != s {
					t.Fatalf("entry %q target = %q, want %q", k, e.Target, s)
				}
			} else if !e.Invalid {
				t.Fatalf("entry %q for non-string value must be invalid", k)
			}
		}
	})
}
