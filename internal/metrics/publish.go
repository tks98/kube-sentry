package metrics

import (
	"fmt"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tks98/kube-sentry/internal/scanner"
)

const (
	LabelGroupAll     = "all"
	labelGroupSummary = "summary"
)

type FieldScope string

const (
	FieldScopeReport        FieldScope = "report"
	FieldScopeVulnerability FieldScope = "vulnerability"
)

var VulnerabilityInfo *prometheus.GaugeVec

type VulnerabilityLabel struct {
	Name   string
	Groups []string
	Scope  FieldScope
}

var metricLabels = []VulnerabilityLabel{
	{
		Name:   "report_name",
		Groups: []string{LabelGroupAll, labelGroupSummary},
		Scope:  FieldScopeReport,
	},
	{
		Name:   "image_namespace",
		Groups: []string{LabelGroupAll, labelGroupSummary},
		Scope:  FieldScopeReport,
	},
	{
		Name:   "image_registry",
		Groups: []string{LabelGroupAll, labelGroupSummary},
		Scope:  FieldScopeReport,
	},
	{
		Name:   "image_repository",
		Groups: []string{LabelGroupAll, labelGroupSummary},
		Scope:  FieldScopeReport,
	},
	{
		Name:   "image_tag",
		Groups: []string{LabelGroupAll, labelGroupSummary},
		Scope:  FieldScopeReport,
	},
	{
		Name:   "image_digest",
		Groups: []string{LabelGroupAll, labelGroupSummary},
		Scope:  FieldScopeReport,
	},
	{
		Name: "severity",
		// Note - Summary metrics use a different severity field than per-vulnerability severity.
		Groups: []string{LabelGroupAll, labelGroupSummary},
		Scope:  FieldScopeVulnerability,
	},
	{
		Name:   "vulnerability_id",
		Groups: []string{LabelGroupAll},
		Scope:  FieldScopeVulnerability,
	},
	{
		Name:   "vulnerable_resource_name",
		Groups: []string{LabelGroupAll},
		Scope:  FieldScopeVulnerability,
	},
	{
		Name:   "installed_resource_version",
		Groups: []string{LabelGroupAll},
		Scope:  FieldScopeVulnerability,
	},
	{
		Name:   "fixed_resource_version",
		Groups: []string{LabelGroupAll},
		Scope:  FieldScopeVulnerability,
	},
	{
		Name:   "vulnerability_title",
		Groups: []string{LabelGroupAll},
		Scope:  FieldScopeVulnerability,
	},
	{
		Name:   "vulnerability_link",
		Groups: []string{LabelGroupAll},
		Scope:  FieldScopeVulnerability,
	},
}

// PublishReportMetrics parses the result, and for each vulnerability, exposes a prometheus metric
func PublishReportMetrics(scanResult *scanner.Result) {
	reportValues := getReportValues(scanResult)

	for _, vuln := range scanResult.TrivyResult.Vulnerabilities {
		vulnValues := valuesForVulnerability(vuln, metricLabels)

		for label, value := range reportValues {
			vulnValues[label] = value
		}

		score := vuln.Vulnerability.CVSS["nvd"].V3Score

		// Expose the metric
		VulnerabilityInfo.With(
			vulnValues,
		).Set(score)
	}
}

func getReportValues(scanResult *scanner.Result) map[string]string {
	result := map[string]string{}

	for _, label := range metricLabels {
		result[label.Name] = reportValueFor(label.Name, scanResult)
	}

	return result

}

func valuesForVulnerability(vuln types.DetectedVulnerability, labels []VulnerabilityLabel) map[string]string {
	result := map[string]string{}
	for _, label := range labels {
		if label.Scope == FieldScopeVulnerability {
			result[label.Name] = vulnValueFor(label.Name, vuln)
		}
	}
	return result
}

func reportValueFor(field string, scanResult *scanner.Result) string {
	switch field {
	case "report_name":
		return fmt.Sprintf("%s:%s", scanResult.Namespace, scanResult.Container.Name)
	case "image_namespace":
		return namespace
	case "image_registry":
		return scanResult.Image.Registry()
	case "image_repository":
		return scanResult.Image.Repository()
	case "image_tag":
		return scanResult.Image.Tag()
	case "image_digest":
		return scanResult.ImageDigest
	default:
		return ""
	}
}

func vulnValueFor(field string, vuln types.DetectedVulnerability) string {
	switch field {
	case "vulnerability_id":
		return vuln.VulnerabilityID
	case "vulnerable_resource_name":
		return vuln.PkgName
	case "installed_resource_version":
		return vuln.InstalledVersion
	case "fixed_resource_version":
		return vuln.FixedVersion
	case "vulnerability_title":
		return vuln.Title
	case "vulnerability_link":
		return vuln.PrimaryURL
	case "severity":
		return vuln.Severity
	default:
		return ""
	}
}
