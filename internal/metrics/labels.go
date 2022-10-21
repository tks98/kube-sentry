package metrics

const (
	LabelGroupAll     = "all"
	labelGroupSummary = "summary"
)

type FieldScope string

const (
	FieldScopeReport        FieldScope = "report"
	FieldScopeVulnerability FieldScope = "vulnerability"
	DefaultLabels           string     = "report_name, image_namespace, image_registry, image_repository, image_tag,image_digest, severity, vulnerability_id, vulnerable_resource_name, installed_resource_version, fixed_resource_version, vulnerability_title, vulnerability_link"
)

type VulnerabilityLabel struct {
	Name   string
	Groups []string
	Scope  FieldScope
}

var VulnerabilityLabels []VulnerabilityLabel
