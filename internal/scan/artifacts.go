package scan

import (
	"path"
	"regexp"
	"strings"

	"github.com/trungminhdo4-glitch/modelgate/internal/finding"
)

const RuleArtifactFormat = "MG-ARTIFACT-001"

var pytorchWeightsName = regexp.MustCompile(`^pytorch_model(?:-[0-9]+-of-[0-9]+)?\.bin$`)

// checkpointFormatFindings uses only tree metadata. A filename indicates a
// serialization capability worth reviewing, not the file's actual contents or
// whether it is malicious. Never fetch or deserialize the artifact here.
func (a *analyzer) checkpointFormatFindings() []finding.Finding {
	var out []finding.Finding
	for file := range a.fileIndex {
		name := strings.ToLower(path.Base(file))
		switch path.Ext(name) {
		case ".pkl", ".pickle", ".pt", ".pth", ".ckpt":
		case ".bin":
			if !pytorchWeightsName.MatchString(name) {
				continue
			}
		default:
			continue
		}
		out = append(out, finding.Finding{
			Rule:        RuleArtifactFormat,
			Severity:    finding.SeverityLow,
			Title:       "Checkpoint filename requires serialization review",
			Message:     "The filename matches a format that can use pickle-based serialization. Artifact contents were not inspected; the name alone does not establish the format, loading behavior, or maliciousness.",
			File:        file,
			Remediation: "Prefer an available safetensors artifact and review the selected loader and its options. Do not deserialize an untrusted artifact to investigate this finding.",
			References:  []string{"https://huggingface.co/docs/hub/en/security-pickle", "https://huggingface.co/docs/safetensors/convert-weights"},
		})
	}
	return out
}
