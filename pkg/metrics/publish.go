package metrics

import (
	"fmt"
	"github.com/aquasecurity/trivy/pkg/types"
	parser "github.com/novln/docker-parser"
	v1 "k8s.io/api/core/v1"
)

// Exporter represents a type which can publish prometheus metrics for scan results
type Exporter struct {
	Container   *v1.Container
	Namespace   string
	TrivyResult *types.Result
	Image       *parser.Reference
	ImageDigest string
}

// NewExporter returns an Exporter type
func NewExporter(container *v1.Container, namespace string, trivyResult *types.Result, image *parser.Reference, imageDigest string) Exporter {

	return Exporter{
		Container:   container,
		Namespace:   namespace,
		TrivyResult: trivyResult,
		Image:       image,
		ImageDigest: imageDigest,
	}
}

// PublishReportMetrics publishes the trivy scan results for each vulnerability
func (e Exporter) PublishReportMetrics() {

	for _, vuln := range e.TrivyResult.Vulnerabilities {

		// retrieve vulnerability information from result
		// convert into metrics prometheus can export
		vulnerabilityMetrics := e.parseVulnerability(vuln)
		score := vuln.Vulnerability.CVSS["nvd"].V3Score

		// publish the metric
		ImageVulnerability.With(
			vulnerabilityMetrics,
		).Set(score)
	}
}

// parseVulnerability uses the detected vulnerability from the trivy scan and converts it into a format prometheus can export
func (e Exporter) parseVulnerability(vuln types.DetectedVulnerability) map[string]string {
	result := map[string]string{}
	for _, label := range VulnerabilityLabels {
		result[label.Name] = e.getVulnerabilityValue(label.Name, vuln)
	}

	return result
}

// getVulnerabilityValue returns the value from the trivy vulnerability which corresponds to the metrics label
func (e Exporter) getVulnerabilityValue(label string, vuln types.DetectedVulnerability) string {

	switch label {
	case "report_name":
		return fmt.Sprintf("%s:%s", e.Namespace, e.Container.Name)
	case "image_namespace":
		return e.Namespace
	case "image_registry":
		return e.Image.Registry()
	case "image_repository":
		return e.Image.Repository()
	case "image_tag":
		return e.Image.Tag()
	case "image_digest":
		return e.ImageDigest
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
