package scan

import (
	"regexp"
	"sort"
	"strings"
)

// loader describes deserialization entry points of one library for the
// MG-DESER rules. Calls are recognised on masked source in three forms:
//
//	pickle.loads(x)                    direct module call (Modules, Receivers)
//	import pickle as pk; pk.loads(x)   aliased module import
//	from pickle import loads; loads(x) imported function (also "as" and "*")
//
// Matching is purely textual. Nothing is imported or executed.
type loader struct {
	// Modules are importable module names, e.g. "pickle". They are matched
	// in import statements and as call receivers.
	Modules []string
	// Receivers are extra conventional receiver names that are not module
	// names themselves (np for numpy, pd for pandas).
	Receivers []string
	// Funcs are the loader functions, e.g. "load", "loads".
	Funcs []string
	// Unsafe, when set, decides from the call's argument text whether the
	// call is reportable. nil means every call is reportable.
	Unsafe func(args string) bool
}

var (
	reImportStmt = regexp.MustCompile(`(?m)(?:^|;)[ \t]*import[ \t]+([^\n;]+)`)
	reFromStmt   = regexp.MustCompile(`(?m)(?:^|;)[ \t]*from[ \t]+([\w.]+)[ \t]+import[ \t]+(\([^)]*\)|[^\n;]+)`)
	reIdent      = regexp.MustCompile(`^[A-Za-z_]\w*$`)

	reWeightsOnlyTrue = regexp.MustCompile(`\bweights_only\s*=\s*True\b`)
	reAllowPickleTrue = regexp.MustCompile(`\ballow_pickle\s*=\s*True\b`)
	reYAMLSafeLoader  = regexp.MustCompile(`\b(?:C?SafeLoader|BaseLoader)\b`)
)

// maxCallArgs caps how far the argument scanner looks for the closing
// parenthesis, so a pathological file cannot make one call site expensive.
const maxCallArgs = 4096

// deser001Loaders are the pickle-family and other code-executing loaders
// reported by MG-DESER-001.
var deser001Loaders = []loader{
	{Modules: []string{"pickle", "cPickle", "_pickle", "dill", "cloudpickle"}, Funcs: []string{"load", "loads", "Unpickler"}},
	{Modules: []string{"marshal"}, Funcs: []string{"load", "loads"}},
	{Modules: []string{"joblib"}, Funcs: []string{"load"}},
	{Modules: []string{"shelve"}, Funcs: []string{"open"}},
	{Modules: []string{"jsonpickle"}, Funcs: []string{"decode", "loads"}},
	{Modules: []string{"pandas"}, Receivers: []string{"pd"}, Funcs: []string{"read_pickle"}},
	{Modules: []string{"numpy"}, Receivers: []string{"np"}, Funcs: []string{"load"},
		Unsafe: func(args string) bool { return reAllowPickleTrue.MatchString(args) }},
	{Modules: []string{"yaml"}, Funcs: []string{"unsafe_load", "unsafe_load_all"}},
	{Modules: []string{"yaml"}, Funcs: []string{"load", "load_all"},
		Unsafe: func(args string) bool { return !reYAMLSafeLoader.MatchString(args) }},
}

// deser002Loaders is torch.load unless weights_only=True is passed.
var deser002Loaders = []loader{
	{Modules: []string{"torch"}, Funcs: []string{"load"},
		Unsafe: func(args string) bool { return !reWeightsOnlyTrue.MatchString(args) }},
}

// loaderCallSites returns the byte offsets of reportable loader calls in
// masked source, in ascending order without duplicates.
func loaderCallSites(masked []byte, loaders []loader) []int {
	modAlias, funcAlias := importBindings(masked)
	seen := map[int]bool{}
	var out []int
	for _, l := range loaders {
		receivers := append(append([]string(nil), l.Modules...), l.Receivers...)
		for _, m := range l.Modules {
			receivers = append(receivers, modAlias[m]...)
		}
		var bare []string
		for _, m := range l.Modules {
			for _, f := range l.Funcs {
				bare = append(bare, funcAlias[m+"."+f]...)
				bare = append(bare, funcAlias[m+".*"]...)
			}
		}
		var res []*regexp.Regexp
		res = append(res, regexp.MustCompile(`\b(?:`+quoteAll(dedupe(receivers))+`)\s*\.\s*(?:`+quoteAll(l.Funcs)+`)\s*\(`))
		if len(bare) > 0 {
			names := dedupe(bare)
			if containsString(names, "*") {
				names = append(removeString(names, "*"), l.Funcs...)
				names = dedupe(names)
			}
			res = append(res, regexp.MustCompile(`\b(?:`+quoteAll(names)+`)\s*\(`))
		}
		for i, re := range res {
			for _, loc := range re.FindAllIndex(masked, -1) {
				start := loc[0]
				if i == 0 && precededByDot(masked, start) {
					continue // obj.pickle.load(...) is not the module
				}
				if i == 1 && !isBareCall(masked, start) {
					continue
				}
				if l.Unsafe != nil && !l.Unsafe(callArgs(masked, loc[1]-1)) {
					continue
				}
				if !seen[start] {
					seen[start] = true
					out = append(out, start)
				}
			}
		}
	}
	sort.Ints(out)
	return out
}

// importBindings collects names bound by import statements: for
// "import pickle as pk" modAlias["pickle"] holds "pk"; for
// "from dill import load as dl" funcAlias["dill.load"] holds "dl"; for
// "from pickle import *" funcAlias["pickle.*"] holds "*".
func importBindings(masked []byte) (map[string][]string, map[string][]string) {
	modAlias := map[string][]string{}
	funcAlias := map[string][]string{}
	for _, m := range reImportStmt.FindAllSubmatch(masked, -1) {
		for _, part := range strings.Split(string(m[1]), ",") {
			fields := strings.Fields(part)
			if len(fields) == 3 && fields[1] == "as" && reIdent.MatchString(fields[2]) {
				modAlias[fields[0]] = append(modAlias[fields[0]], fields[2])
			}
		}
	}
	for _, m := range reFromStmt.FindAllSubmatch(masked, -1) {
		mod := string(m[1])
		list := strings.Trim(strings.TrimSpace(string(m[2])), "()")
		for _, part := range strings.Split(list, ",") {
			fields := strings.Fields(part)
			switch {
			case len(fields) == 1 && fields[0] == "*":
				funcAlias[mod+".*"] = append(funcAlias[mod+".*"], "*")
			case len(fields) == 1 && reIdent.MatchString(fields[0]):
				funcAlias[mod+"."+fields[0]] = append(funcAlias[mod+"."+fields[0]], fields[0])
			case len(fields) == 3 && fields[1] == "as" && reIdent.MatchString(fields[0]) && reIdent.MatchString(fields[2]):
				funcAlias[mod+"."+fields[0]] = append(funcAlias[mod+"."+fields[0]], fields[2])
			}
		}
	}
	return modAlias, funcAlias
}

// callArgs returns the text between the parenthesis at open and its
// matching close parenthesis (or up to maxCallArgs bytes if unbalanced).
// Masked source has strings blanked, so parentheses inside literals do not
// confuse the count.
func callArgs(masked []byte, open int) string {
	if open < 0 || open >= len(masked) || masked[open] != '(' {
		return ""
	}
	depth := 0
	end := open + maxCallArgs
	if end > len(masked) {
		end = len(masked)
	}
	for i := open; i < end; i++ {
		switch masked[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return string(masked[open+1 : i])
			}
		}
	}
	return string(masked[open+1 : end])
}

// precededByDot reports whether the identifier at start is an attribute
// access (the previous non-blank byte is a dot).
func precededByDot(src []byte, start int) bool {
	p := start - 1
	for p >= 0 && (src[p] == ' ' || src[p] == '\t') {
		p--
	}
	return p >= 0 && src[p] == '.'
}

// isBareCall accepts name(...) but rejects obj.name(...) and the
// definitions "def name(" and "class name(".
func isBareCall(src []byte, start int) bool {
	if precededByDot(src, start) {
		return false
	}
	p := start - 1
	for p >= 0 && (src[p] == ' ' || src[p] == '\t') {
		p--
	}
	q := p
	for q >= 0 && isIdentByte(src[q]) {
		q--
	}
	prev := string(src[q+1 : p+1])
	return prev != "def" && prev != "class"
}

func quoteAll(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = regexp.QuoteMeta(n)
	}
	return strings.Join(q, "|")
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func containsString(in []string, s string) bool {
	for _, v := range in {
		if v == s {
			return true
		}
	}
	return false
}

func removeString(in []string, s string) []string {
	var out []string
	for _, v := range in {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}
