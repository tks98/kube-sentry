package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"strings"
)

var ImageVulnerability *prometheus.GaugeVec

// RegisterVulnerabilityCollector registers a prometheus type for image vulnerabilities
func RegisterVulnerabilityCollector(registry *prometheus.Registry, l string) {

	// determine which labels to use with ImageVulnerability exporter
	// if none supplied, use default (all)
	var labels []VulnerabilityLabel
	if l == "" {
		labels = GetMetricsLabels(DefaultLabels)
	} else {
		labels = GetMetricsLabels(l)
	}

	// set global labels
	VulnerabilityLabels = labels

	// register metric
	ImageVulnerability = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "image_vulnerability",
			Help: "Indicates the presence of a CVE in an image.",
		},
		GetLabelNames(labels),
	)

	registry.MustRegister(ImageVulnerability)
}

func GetLabelNames(list []VulnerabilityLabel) []string {
	var l []string
	for _, label := range list {
		l = append(l, label.Name)
	}
	return l
}

// GetMetricsLabels returns a slice of VulnerabilityLabels from the labels string supplied in the config
// l = "image_digest, report_name, image_namespace.. etc"
func GetMetricsLabels(l string) []VulnerabilityLabel {

	var vulnerabilityLabels []VulnerabilityLabel

	labels := strings.Split(l, ",")

	for _, label := range labels {

		label = strings.Trim(label, "\"")
		label = strings.Trim(label, "\n")
		label = strings.Trim(label, "")
		label = strings.Trim(label, " ")

		var kind FieldScope
		if strings.Contains(label, "vulnerability") {
			kind = FieldScopeVulnerability
		} else {
			kind = FieldScopeReport
		}

		vulnerabilityLabels = append(vulnerabilityLabels, VulnerabilityLabel{
			Name:   label,
			Groups: []string{LabelGroupAll, labelGroupSummary},
			Scope:  kind,
		})
	}

	return vulnerabilityLabels
}
