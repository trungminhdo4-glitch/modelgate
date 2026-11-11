package scan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/trungminhdo4-glitch/modelgate/internal/finding"
	"github.com/trungminhdo4-glitch/modelgate/internal/hf"
	"github.com/trungminhdo4-glitch/modelgate/internal/pin"
)

// Default limits bound memory and runtime on hostile repositories.
const (
	DefaultMaxFiles     = 64
	DefaultMaxFileBytes = 1 << 20 // 1 MiB per analyzed file
	maxReadmeBytes      = 1 << 20
)

// Rule identifiers produced by the orchestration layer (everything that is
// not a Python pattern rule lives here).
const (
	RuleConfigFlag    = "MG-TRUST-001"
	RuleAutoMap       = "MG-TRUST-002"
	RuleCardMentions  = "MG-TRUST-003"
	RuleAutoMapBadVal = "MG-CFG-002"
	RuleAutoMapUnsafe = "MG-AUTO-001"
	RuleAutoMapMiss   = "MG-MISS-001"
	RuleConfigInvalid = "MG-CFG-001"
	RuleLimit         = "MG-LIMIT-001"
	RuleLFS           = "MG-LFS-001"
	RuleDatasetScript = "MG-DATASET-001"
	RulePinMismatch   = "MG-PIN-001"
	RulePinOK         = "MG-PIN-002"
	RulePinMissing    = "MG-PIN-003"
)

// Options configures one analysis run.
type Options struct {
	RepoType     string // hf.RepoModel or hf.RepoDataset
	RepoID       string // e.g. "org/model"
	Revision     string // branch, tag or SHA; empty = default branch
	Pin          string // expected upstream SHA; empty = no pin check
	MaxFiles     int    // cap on analyzed Python files (default 64)
	MaxFileBytes int64  // cap per analyzed file (default 1 MiB)
}

func (o *Options) withDefaults() {
	if o.RepoType == "" {
		o.RepoType = hf.RepoModel
	}
	if o.MaxFiles <= 0 {
		o.MaxFiles = DefaultMaxFiles
	}
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = DefaultMaxFileBytes
	}
}

// Result is the complete outcome of one read-only analysis run.
type Result struct {
	RepoType       string            `json:"repo_type"`
	RepoID         string            `json:"repo_id"`
	Revision       string            `json:"revision"`
	PinnedRevision string            `json:"pinned_revision,omitempty"`
	Tree           []hf.TreeEntry    `json:"-"`
	AnalyzedFiles  []string          `json:"analyzed_files"`
	AutoMapTargets []string          `json:"auto_map_targets,omitempty"`
	Trust          TrustAssessment   `json:"trust_remote_code"`
	Findings       []finding.Finding `json:"findings"`
	Delta          *pin.Delta        `json:"delta,omitempty"`
}

// Analyze performs a full, read-only supply-chain check of one repository.
// It performs GET requests only and never writes to any filesystem.
func Analyze(ctx context.Context, f hf.Fetcher, opts Options) (*Result, error) {
	if f == nil {
		return nil, errors.New("scan: nil fetcher")
	}
	opts.withDefaults()
	if err := hf.ValidateRepoType(opts.RepoType); err != nil {
		return nil, err
	}
	if err := hf.ValidateRepoID(opts.RepoID); err != nil {
		return nil, err
	}
	if opts.Revision != "" {
		if err := hf.ValidateRevision(opts.Revision); err != nil {
			return nil, err
		}
	}
	if opts.Pin != "" {
		if err := hf.ValidateRevision(opts.Pin); err != nil {
			return nil, fmt.Errorf("pin: %w", err)
		}
	}

	meta, err := f.Meta(ctx, opts.RepoType, opts.RepoID, opts.Revision)
	if err != nil {
		return nil, fmt.Errorf("metadata for %s: %w", opts.RepoID, err)
	}
	rev := meta.Sha
	if rev == "" {
		rev = opts.Revision
	}
	if rev == "" {
		rev = "main"
	}

	tree, err := f.Tree(ctx, opts.RepoType, opts.RepoID, rev)
	if err != nil {
		return nil, fmt.Errorf("tree for %s@%s: %w", opts.RepoID, rev, err)
	}

	current := newAnalyzer(f, opts, rev, tree)
	files, findings, trust, targets, err := current.run(ctx)
	if err != nil {
		return nil, err
	}

	res := &Result{
		RepoType:       opts.RepoType,
		RepoID:         opts.RepoID,
		Revision:       rev,
		PinnedRevision: opts.Pin,
		Tree:           tree,
		AnalyzedFiles:  files,
		AutoMapTargets: targets,
		Trust:          trust,
		Findings:       findings,
	}

	if opts.Pin != "" {
		delta, pinFindings, err := checkPin(ctx, f, opts, rev, tree, res.Findings)
		if err != nil {
			return nil, err
		}
		res.Delta = delta
		res.Findings = append(res.Findings, pinFindings...)
	}

	finding.SortFindings(res.Findings)
	return res, nil
}

// checkPin compares the resolved upstream revision against the pinned SHA and
// produces both the delta section and the corresponding findings.
func checkPin(ctx context.Context, f hf.Fetcher, opts Options, rev string, tree []hf.TreeEntry, currentFindings []finding.Finding) (*pin.Delta, []finding.Finding, error) {
	if opts.Pin == rev {
		return nil, []finding.Finding{{
			Rule:        RulePinOK,
			Severity:    finding.SeverityInfo,
			Title:       "Pinned revision verified",
			Message:     fmt.Sprintf("Upstream serves exactly the pinned revision %s.", shortSHA(rev)),
			Remediation: "Keep the pin updated on your own review cadence.",
			References:  []string{"https://github.com/trungminhdo4-glitch/modelgate#commit-sha-pinning"},
		}}, nil
	}

	pinnedTree, err := f.Tree(ctx, opts.RepoType, opts.RepoID, opts.Pin)
	if err != nil {
		if hf.IsNotFound(err) {
			return nil, []finding.Finding{{
				Rule:        RulePinMissing,
				Severity:    finding.SeverityHigh,
				Title:       "Pinned revision no longer exists upstream",
				Message:     fmt.Sprintf("Revision %s was not found upstream (rewritten history or deleted commit).", opts.Pin),
				Remediation: "Re-review the current revision, then update the pin. Do not load code you have not reviewed.",
			}}, nil
		}
		return nil, nil, fmt.Errorf("tree for pinned revision %s: %w", opts.Pin, err)
	}

	pinned := newAnalyzer(f, opts, opts.Pin, pinnedTree)
	_, pinnedFindings, _, _, err := pinned.run(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("analyzing pinned revision %s: %w", opts.Pin, err)
	}

	delta := &pin.Delta{
		Pinned:  opts.Pin,
		Current: rev,
		Changes: pin.DiffTrees(pinnedTree, tree),
	}
	delta.NewFindings, delta.ResolvedFindings = pin.DiffFindings(pinnedFindings, currentFindings)

	msg := fmt.Sprintf("Upstream moved: pinned %s != current %s (%d file(s) changed).", shortSHA(opts.Pin), shortSHA(rev), len(delta.Changes))
	return delta, []finding.Finding{{
		Rule:        RulePinMismatch,
		Severity:    finding.SeverityHigh,
		Title:       "Upstream revision differs from pin",
		Message:     msg,
		Remediation: "Re-run the review against the current revision and update the pin only after approval.",
		References:  []string{"https://github.com/trungminhdo4-glitch/modelgate#commit-sha-pinning"},
	}}, nil
}

func shortSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

// analyzer holds the immutable state of one revision analysis.
type analyzer struct {
	f         hf.Fetcher
	opts      Options
	rev       string
	fileIndex map[string]hf.TreeEntry
}

func newAnalyzer(f hf.Fetcher, opts Options, rev string, tree []hf.TreeEntry) *analyzer {
	idx := make(map[string]hf.TreeEntry, len(tree))
	for _, e := range tree {
		// The tree is untrusted input: only a known "directory" is excluded.
		// Any other type ("file", "" or a hostile unknown value) is treated
		// as a file so a server cannot hide content by lying about the type.
		if e.Type == "directory" {
			continue
		}
		idx[e.Path] = e
	}
	return &analyzer{f: f, opts: opts, rev: rev, fileIndex: idx}
}

// run analyzes one revision: config, auto_map targets, dataset scripts, card.
func (a *analyzer) run(ctx context.Context) (files []string, findings []finding.Finding, trust TrustAssessment, targets []string, err error) {
	cfg, cfgFindings, err := a.loadConfig(ctx)
	if err != nil {
		return nil, nil, trust, nil, err
	}
	findings = append(findings, cfgFindings...)

	if a.opts.RepoType == hf.RepoDataset {
		targets, trust.DatasetScripts = a.datasetScripts()
		if len(targets) > 0 {
			findings = append(findings, finding.Finding{
				Rule:        RuleDatasetScript,
				Severity:    finding.SeverityMedium,
				Title:       "Dataset repository ships Python scripts",
				Message:     fmt.Sprintf("%d Python script(s) present; dataset loading scripts execute locally when used with trust_remote_code.", len(targets)),
				File:        targets[0],
				Remediation: "Review every script before loading, or load the dataset with scripts disabled.",
				References:  []string{"https://huggingface.co/docs/datasets/loading#loading-dataset-scripts"},
			})
		}
	} else {
		targets, findings = a.autoMapTargets(cfg, findings)
	}

	// Trust surface summary from config and card.
	if cfg != nil {
		if cfg.TrustRemoteCode != nil && *cfg.TrustRemoteCode {
			trust.ConfigFlag = true
			findings = append(findings, finding.Finding{
				Rule:        RuleConfigFlag,
				Severity:    finding.SeverityMedium,
				Title:       "config.json sets trust_remote_code",
				Message:     "The repository configuration enables trust_remote_code, which opts into importing repository Python code.",
				File:        "config.json",
				Remediation: "Only proceed after reviewing every referenced Python file, or pin and vendor them.",
				References:  []string{"https://huggingface.co/docs/hub/trust-remote-code"},
			})
		}
		if entries := cfg.AutoMapEntries(); len(entries) > 0 {
			trust.AutoMapCount = len(entries)
			findings = append(findings, finding.Finding{
				Rule:        RuleAutoMap,
				Severity:    finding.SeverityMedium,
				Title:       "auto_map exposes remote code extension points",
				Message:     fmt.Sprintf("auto_map defines %d entry point(s): %s", len(entries), summarizeEntries(entries)),
				File:        "config.json",
				Remediation: "Review the referenced files (ModelGate does this statically) before loading with trust_remote_code.",
				References:  []string{"https://huggingface.co/docs/hub/trust-remote-code"},
			})
		}
	}

	readmePath, ok := a.firstOf("README.md", "readme.md")
	if ok {
		data, rerr := a.fetch(ctx, readmePath, maxReadmeBytes)
		switch {
		case rerr == nil:
			n := CountCardMentions(data)
			trust.CardMentions = n
			if n > 0 {
				findings = append(findings, finding.Finding{
					Rule:        RuleCardMentions,
					Severity:    finding.SeverityLow,
					Title:       "Model card documents trust_remote_code usage",
					Message:     fmt.Sprintf("README mentions trust_remote_code=%v %d time(s).", true, n),
					File:        readmePath,
					Remediation: "Treat the card's usage snippet as an instruction to run third-party code; review first.",
					References:  []string{"https://huggingface.co/docs/hub/trust-remote-code"},
				})
			}
		default:
			var se *skipError
			if errors.As(rerr, &se) {
				findings = append(findings, se.f)
			} else if !hf.IsNotFound(rerr) {
				return nil, nil, trust, nil, rerr
			}
		}
	}

	// Cap and sort targets, then scan them.
	targets = uniqueSorted(targets)
	if len(targets) > a.opts.MaxFiles {
		truncated := targets[:a.opts.MaxFiles]
		findings = append(findings, finding.Finding{
			Rule:        RuleLimit,
			Severity:    finding.SeverityMedium,
			Title:       "Analysis file limit reached",
			Message:     fmt.Sprintf("Repository has %d candidate file(s); only the first %d (lexicographic) were analyzed.", len(targets), a.opts.MaxFiles),
			Remediation: "Raise the limit deliberately or split the review; do not assume the rest is clean.",
		})
		targets = truncated
	}

	for _, path := range targets {
		analyzed, ferr := a.scanTarget(ctx, path)
		if ferr != nil {
			var se *skipError
			if errors.As(ferr, &se) {
				findings = append(findings, se.f)
				continue
			}
			return nil, nil, trust, nil, ferr
		}
		files = append(files, path)
		findings = append(findings, analyzed...)
	}
	return files, findings, trust, targets, nil
}

// errSkipped is the sentinel every skipError matches. A skip carries its
// explaining finding inside the error so callers can either surface it or
// abort.
var errSkipped = errors.New("file skipped")

type skipError struct{ f finding.Finding }

func (e *skipError) Error() string { return "skipped: " + e.f.Title }
func (e *skipError) Is(target error) bool {
	return target == errSkipped
}

// loadConfig fetches and parses config.json if present.
func (a *analyzer) loadConfig(ctx context.Context) (*ModelConfig, []finding.Finding, error) {
	if _, ok := a.firstOf("config.json"); !ok {
		return nil, nil, nil
	}
	data, err := a.fetch(ctx, "config.json", a.opts.MaxFileBytes)
	if err != nil {
		var se *skipError
		if errors.As(err, &se) {
			return nil, []finding.Finding{se.f}, nil
		}
		if hf.IsNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	cfg, perr := ParseConfig(data)
	if perr != nil {
		return nil, []finding.Finding{{
			Rule:        RuleConfigInvalid,
			Severity:    finding.SeverityMedium,
			Title:       "config.json could not be parsed",
			Message:     "The model config is not valid JSON; trust_remote_code and auto_map could not be fully evaluated.",
			File:        "config.json",
			Remediation: "Inspect the config manually before loading the model.",
		}}, nil
	}
	return cfg, nil, nil
}

// autoMapTargets resolves auto_map entries for a model repository.
func (a *analyzer) autoMapTargets(cfg *ModelConfig, findings []finding.Finding) ([]string, []finding.Finding) {
	if cfg == nil {
		return nil, findings
	}
	var targets []string
	for _, e := range cfg.AutoMapEntries() {
		if e.Invalid {
			findings = append(findings, finding.Finding{
				Rule:        RuleAutoMapBadVal,
				Severity:    finding.SeverityMedium,
				Title:       "auto_map value has unexpected type",
				Message:     fmt.Sprintf("auto_map[%q] is not a string; the referenced code path could not be resolved.", e.Key),
				File:        "config.json",
				Remediation: "Fix the config or inspect the repository manually.",
			})
			continue
		}
		path, err := ResolveAutoMapPath(e.Target)
		if err != nil {
			findings = append(findings, finding.Finding{
				Rule:        RuleAutoMapUnsafe,
				Severity:    finding.SeverityMedium,
				Title:       "auto_map target rejected",
				Message:     fmt.Sprintf("auto_map[%q]=%q: %v", e.Key, e.Target, err),
				File:        "config.json",
				Evidence:    e.Target,
				Remediation: "An auto_map target must resolve to a plain repository file path. Inspect the config manually.",
			})
			continue
		}
		targets = append(targets, path)
	}
	return targets, findings
}

// datasetScripts lists every Python file of a dataset repository.
func (a *analyzer) datasetScripts() ([]string, bool) {
	var out []string
	for path := range a.fileIndex {
		if strings.HasSuffix(path, ".py") {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out, len(out) > 0
}

// scanTarget fetches one Python target and runs the static analyzer on it.
func (a *analyzer) scanTarget(ctx context.Context, path string) ([]finding.Finding, error) {
	entry, ok := a.fileIndex[path]
	if !ok {
		return nil, &skipError{f: finding.Finding{
			Rule:        RuleAutoMapMiss,
			Severity:    finding.SeverityMedium,
			Title:       "auto_map target not present in repository",
			Message:     fmt.Sprintf("auto_map references %q but the file is not in the repository tree.", path),
			File:        path,
			Remediation: "Loading would fail or fetch unexpected content; inspect the repository before use.",
		}}
	}
	if entry.Size > a.opts.MaxFileBytes {
		return nil, &skipError{f: finding.Finding{
			Rule:        RuleLimit,
			Severity:    finding.SeverityMedium,
			Title:       "File exceeds analysis size limit",
			Message:     fmt.Sprintf("%s is %d bytes (limit %d); it was not analyzed.", path, entry.Size, a.opts.MaxFileBytes),
			File:        path,
			Remediation: "Review the file manually or raise the limit deliberately.",
		}}
	}
	data, err := a.fetch(ctx, path, a.opts.MaxFileBytes)
	if err != nil {
		if errors.Is(err, errSkipped) {
			return nil, err
		}
		if hf.IsNotFound(err) {
			return nil, &skipError{f: finding.Finding{
				Rule:        RuleAutoMapMiss,
				Severity:    finding.SeverityMedium,
				Title:       "auto_map target not retrievable",
				Message:     fmt.Sprintf("Fetching %q failed with not-found.", path),
				File:        path,
				Remediation: "Inspect the repository before use.",
			}}
		}
		return nil, err
	}
	if isLFSPointer(data) {
		return nil, &skipError{f: finding.Finding{
			Rule:        RuleLFS,
			Severity:    finding.SeverityMedium,
			Title:       "Target stored via Git LFS, content not analyzed",
			Message:     fmt.Sprintf("%s is a Git LFS pointer; ModelGate does not download LFS objects.", path),
			File:        path,
			Remediation: "Retrieve and review the object out-of-band if you need assurance.",
		}}
	}
	return AnalyzePython(path, data), nil
}

// fetch downloads one file with limit enforcement. Oversized files surface as
// a skipError carrying a finding instead of an aborted run.
func (a *analyzer) fetch(ctx context.Context, path string, limit int64) ([]byte, error) {
	if entry, ok := a.fileIndex[path]; ok && entry.Size > limit {
		return nil, &skipError{f: finding.Finding{
			Rule:        RuleLimit,
			Severity:    finding.SeverityMedium,
			Title:       "File exceeds analysis size limit",
			Message:     fmt.Sprintf("%s is %d bytes (limit %d); it was not analyzed.", path, entry.Size, limit),
			File:        path,
			Remediation: "Review the file manually or raise the limit deliberately.",
		}}
	}
	data, err := a.f.Raw(ctx, a.opts.RepoType, a.opts.RepoID, a.rev, path)
	if err != nil {
		if errors.Is(err, hf.ErrTooLarge) {
			return nil, &skipError{f: finding.Finding{
				Rule:        RuleLimit,
				Severity:    finding.SeverityMedium,
				Title:       "Response exceeded size limit",
				Message:     fmt.Sprintf("%s exceeded the response size cap and was not analyzed.", path),
				File:        path,
				Remediation: "Retrieve the file out-of-band for manual review.",
			}}
		}
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, &skipError{f: finding.Finding{
			Rule:        RuleLimit,
			Severity:    finding.SeverityMedium,
			Title:       "File exceeds analysis size limit",
			Message:     fmt.Sprintf("%s is %d bytes (limit %d); it was not analyzed.", path, len(data), limit),
			File:        path,
			Remediation: "Review the file manually or raise the limit deliberately.",
		}}
	}
	return data, nil
}

var lfsPointerPrefix = []byte("version https://git-lfs.github.com/spec/v1")

func isLFSPointer(data []byte) bool {
	return bytes.HasPrefix(data, lfsPointerPrefix)
}

// firstOf returns the first path present in the tree among candidates.
func (a *analyzer) firstOf(candidates ...string) (string, bool) {
	for _, c := range candidates {
		if _, ok := a.fileIndex[c]; ok {
			return c, true
		}
	}
	return "", false
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// summarizeEntries renders at most five auto_map entries for the message.
func summarizeEntries(entries []AutoMapEntry) string {
	parts := make([]string, 0, len(entries))
	for i, e := range entries {
		if i == 5 {
			parts = append(parts, fmt.Sprintf("(+%d more)", len(entries)-5))
			break
		}
		if e.Invalid {
			parts = append(parts, fmt.Sprintf("%s -> <invalid>", e.Key))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s -> %s", e.Key, e.Target))
	}
	return strings.Join(parts, ", ")
}
