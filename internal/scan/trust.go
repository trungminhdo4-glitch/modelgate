package scan

import (
	"regexp"
)

// TrustAssessment summarises everything the check learned about the remote
// code trust surface of one repository.
type TrustAssessment struct {
	// ConfigFlag is true when config.json sets trust_remote_code.
	ConfigFlag bool `json:"config_flag"`
	// AutoMapCount is the number of auto_map entry points found.
	AutoMapCount int `json:"auto_map_count"`
	// CardMentions counts trust_remote_code=... occurrences in the model card.
	CardMentions int `json:"card_mentions"`
	// DatasetScripts is true for dataset repositories with Python scripts.
	DatasetScripts bool `json:"dataset_scripts"`
}

var trustFlagPattern = regexp.MustCompile(`(?i)trust_remote_code\s*=\s*(?:True|true|1)`)

// CountCardMentions counts documented trust_remote_code usages in a README /
// model card. The card is treated as plain text; it is never rendered or
// executed.
func CountCardMentions(readme []byte) int {
	return len(trustFlagPattern.FindAllIndex(readme, -1))
}
