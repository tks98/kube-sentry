package metrics

import (
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
