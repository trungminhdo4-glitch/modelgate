// Package cli implements the modelgate command line interface.
//
// The CLI writes to the filesystem only when the user explicitly passes
// --out or --sbom; every other path is read-only, and all repository access
// goes through the read-only Hugging Face client.
package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/trungminhdo4-glitch/modelgate/internal/finding"
	"github.com/trungminhdo4-glitch/modelgate/internal/hf"
	"github.com/trungminhdo4-glitch/modelgate/internal/report"
	"github.com/trungminhdo4-glitch/modelgate/internal/sbom"
	"github.com/trungminhdo4-glitch/modelgate/internal/scan"
)

// Exit codes (documented in the README).
const (
	ExitOK       = 0
	ExitFindings = 1
	ExitError    = 2
)

// FetcherFactory builds the read-only API client; tests inject fixtures.
type FetcherFactory func(baseURL string, timeout time.Duration) (hf.Fetcher, error)

// App carries all injectable dependencies of the CLI.
type App struct {
	Out        io.Writer
	Err        io.Writer
	Version    string
	Now        func() time.Time
	NewFetcher FetcherFactory
	Home       string // homepage used in reports
}

// New returns the production application wiring.
func New() *App {
	return &App{
		Out:     os.Stdout,
		Err:     os.Stderr,
		Version: "dev",
		Now:     time.Now,
		Home:    report.DefaultHomepage,
		NewFetcher: func(baseURL string, timeout time.Duration) (hf.Fetcher, error) {
			return hf.NewClient(baseURL, timeout)
		},
	}
}

// Run dispatches a subcommand and returns the process exit code.
func (a *App) Run(ctx context.Context, args []string) int {
	if len(args) == 0 {
		a.usage()
		return ExitError
	}
	switch args[0] {
	case "check":
		return a.cmdCheck(ctx, args[1:])
	case "rules":
		return a.cmdRules(args[1:])
	case "version", "--version", "-v":
		fmt.Fprintf(a.Out, "modelgate %s\n", a.Version)
		return ExitOK
	case "help", "--help", "-h":
		a.usage()
		return ExitOK
	default:
		fmt.Fprintf(a.Err, "modelgate: unknown command %q\n\n", args[0])
		a.usage()
		return ExitError
	}
}

func (a *App) usage() {
	io.WriteString(a.Err, `modelgate — static, non-executing supply-chain checks for Hugging Face repositories

Usage:
  modelgate check <repo-id> [flags]   read-only security check of one repository
  modelgate rules [--format json]     list the static pattern rules
  modelgate version                   print the version

Run "modelgate check -h" for check flags.
`)
}

func (a *App) cmdCheck(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	fs.Usage = func() {
		fmt.Fprintln(a.Err, "usage: modelgate check <repo-id> [flags]")
		fs.PrintDefaults()
	}
	repoType := fs.String("type", "model", "repository type: model or dataset")
	revision := fs.String("revision", "", "branch, tag or commit SHA to check (default: repository default branch)")
	pin := fs.String("pin", "", "expected commit SHA; emits a delta report when upstream differs")
	format := fs.String("format", "text", "output format: text, json, sigma or sarif")
	out := fs.String("out", "", "write the report to this file instead of stdout (only filesystem write)")
	sbomOut := fs.String("sbom", "", "write a CycloneDX 1.6 SBOM to this file (only filesystem write)")
	failOnStr := fs.String("fail-on", "high", "minimum severity that fails the check: info, low, medium, high or critical")
	apiURL := fs.String("api-url", "https://huggingface.co", "Hugging Face compatible API base URL (GET only)")
	timeout := fs.Duration("timeout", 30*time.Second, "overall timeout for the check")

	if err := fs.Parse(splitArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(a.Err, "modelgate check: exactly one <repo-id> is required")
		fs.Usage()
		return ExitError
	}
	repoID := fs.Arg(0)
	failOn, err := finding.ParseSeverity(*failOnStr)
	if err != nil {
		fmt.Fprintf(a.Err, "modelgate check: --fail-on: %v\n", err)
		return ExitError
	}
	if !validFormat(*format) {
		fmt.Fprintf(a.Err, "modelgate check: --format must be text, json, sigma or sarif (got %q)\n", *format)
		return ExitError
	}
	if err := hf.ValidateRepoType(*repoType); err != nil {
		fmt.Fprintf(a.Err, "modelgate check: --type: %v\n", err)
		return ExitError
	}
	if *timeout <= 0 {
		fmt.Fprintln(a.Err, "modelgate check: --timeout must be a positive duration")
		return ExitError
	}

	fetcher, err := a.NewFetcher(*apiURL, *timeout)
	if err != nil {
		fmt.Fprintf(a.Err, "modelgate check: %v\n", err)
		return ExitError
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	res, err := scan.Analyze(ctx, fetcher, scan.Options{
		RepoType: *repoType,
		RepoID:   repoID,
		Revision: *revision,
		Pin:      *pin,
	})
	if err != nil {
		fmt.Fprintf(a.Err, "modelgate check: %v\n", err)
		return ExitError
	}
	if err := ctx.Err(); err != nil {
		fmt.Fprintf(a.Err, "modelgate check: %v\n", err)
		return ExitError
	}

	rep, err := report.Build(res, report.BuildOptions{
		ToolVersion: a.Version,
		Homepage:    a.Home,
		Now:         a.Now(),
		FailOn:      failOn,
	})
	if err != nil {
		fmt.Fprintf(a.Err, "modelgate check: %v\n", err)
		return ExitError
	}

	data, err := render(rep, *format)
	if err != nil {
		fmt.Fprintf(a.Err, "modelgate check: %v\n", err)
		return ExitError
	}

	if *out != "" {
		if err := os.WriteFile(*out, data, 0o644); err != nil {
			fmt.Fprintf(a.Err, "modelgate check: writing --out: %v\n", err)
			return ExitError
		}
	} else {
		if _, err := a.Out.Write(data); err != nil {
			fmt.Fprintf(a.Err, "modelgate check: %v\n", err)
			return ExitError
		}
	}

	if *sbomOut != "" {
		bom := sbom.Build(res, sbom.Options{
			ToolName:    "modelgate",
			ToolVersion: a.Version,
			Homepage:    a.Home,
			Timestamp:   a.Now(),
		})
		sbomData, err := bom.JSON()
		if err != nil {
			fmt.Fprintf(a.Err, "modelgate check: %v\n", err)
			return ExitError
		}
		if err := os.WriteFile(*sbomOut, sbomData, 0o644); err != nil {
			fmt.Fprintf(a.Err, "modelgate check: writing --sbom: %v\n", err)
			return ExitError
		}
	}

	s := rep.Summary
	fmt.Fprintf(a.Err, "modelgate: %d finding(s) (worst=%s, fail-on=%s) — %s@%s\n",
		len(rep.Findings), s.Worst, s.FailOn, rep.Repo.ID, rep.Repo.Revision)
	if s.ExitCode == ExitFindings {
		fmt.Fprintln(a.Err, "WARNING: findings at or above fail-on — do not load this revision without review.")
	}
	return s.ExitCode
}

func (a *App) cmdRules(args []string) int {
	fs := flag.NewFlagSet("rules", flag.ContinueOnError)
	fs.SetOutput(a.Err)
	format := fs.String("format", "text", "output format: text or json")
	fs.Usage = func() {
		fmt.Fprintln(a.Err, "usage: modelgate rules [--format text|json]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(splitArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitError
	}
	rules := scan.Rules()
	switch *format {
	case "text":
		for _, r := range rules {
			fmt.Fprintf(a.Out, "%-13s %-9s %s\n", r.ID, r.Severity, r.Title)
		}
	case "json":
		data, err := marshalRules(rules)
		if err != nil {
			fmt.Fprintf(a.Err, "modelgate rules: %v\n", err)
			return ExitError
		}
		a.Out.Write(data)
	default:
		fmt.Fprintf(a.Err, "modelgate rules: --format must be text or json (got %q)\n", *format)
		return ExitError
	}
	return ExitOK
}

// splitArgs reorders argv so that flags and their values precede the
// positional arguments. Go's flag package stops parsing at the first
// non-flag argument, so "check <repo-id> --format json" would otherwise
// silently ignore every flag after the repo id (and exit 2 with
// "exactly one <repo-id> is required"). The token multiset is preserved;
// a "--" terminator, if present, is re-emitted directly in front of the
// positionals so the meaning of every token stays unchanged.
func splitArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positionals []string
	terminated := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case terminated:
			positionals = append(positionals, arg)
		case arg == "--":
			terminated = true
		case len(arg) > 1 && arg[0] == '-':
			flags = append(flags, arg)
			name := arg[1:]
			if len(name) > 0 && name[0] == '-' {
				name = name[1:]
			}
			if strings.IndexByte(name, '=') >= 0 {
				continue // value is attached: --flag=value
			}
			if f := fs.Lookup(name); f == nil || !isBoolFlag(f) {
				// Unknown or value-taking flag consumes the next token
				// exactly like flag.Parse would.
				if i+1 < len(args) {
					i++
					flags = append(flags, args[i])
				}
			}
		default:
			positionals = append(positionals, arg)
		}
	}
	if terminated {
		flags = append(flags, "--")
	}
	return append(flags, positionals...)
}

// isBoolFlag reports whether the flag carries its own value semantics
// (--verbose, --verbose=false) and therefore needs no separate argument.
func isBoolFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

// render produces the requested output format for a finished report.
func render(rep *report.Report, format string) ([]byte, error) {
	switch format {
	case "json":
		return rep.JSON()
	case "sigma":
		return rep.Sigma()
	case "sarif":
		return rep.SARIF()
	default:
		var buf bytes.Buffer
		if err := rep.Text(&buf); err != nil {
			return nil, err
		}
		return buf.Bytes(), nil
	}
}

func validFormat(f string) bool {
	switch f {
	case "text", "json", "sigma", "sarif":
		return true
	default:
		return false
	}
}

// marshalRules renders the rule catalogue as indented JSON with a newline.
func marshalRules(rules []scan.RuleInfo) ([]byte, error) {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
