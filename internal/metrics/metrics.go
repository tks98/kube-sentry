package metrics

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

const (
	namespace        = "namespace"
	name             = "name"
	image_registry   = "image_registry"
	image_repository = "image_repository"
	image_tag        = "image_tag"
	image_digest     = "image_digest"
	vulnerabilities  = "vulnerabilities"
)

type VulnerabilityScanReport struct{}
type FileSystemScanReport struct{}
type LicenseScanReport struct{}

type ResultsMetricsExporter struct {
}

func ServePrometheusMetrics(port string) {
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(port, nil)
}

func ExportReport(report *types.Report, namespace string) {

}
