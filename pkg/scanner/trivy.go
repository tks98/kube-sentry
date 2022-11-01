package scanner

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/types"
	parser "github.com/novln/docker-parser"
	kwhlog "github.com/slok/kubewebhook/v2/pkg/log"
	"github.com/tks98/kube-sentry/pkg/exec"
	"github.com/tks98/kube-sentry/pkg/metrics"
	v1 "k8s.io/api/core/v1"
)

// Scanner represents a trivy scanner
type Scanner struct {
	RemoteURL string
	Insecure  bool
	Logger    kwhlog.Logger
}

// NewScanner returns a Scanner
func NewScanner(remoteURL string, insecure bool, logger kwhlog.Logger, scheme string) (*Scanner, error) {
	if remoteURL == "" {
		return nil, fmt.Errorf("remote url must be set for trivy scanner")
	}

	address := fmt.Sprintf("%s://%s", scheme, remoteURL)

	return &Scanner{
		RemoteURL: address,
		Insecure:  insecure,
		Logger:    logger,
	}, nil
}

// ScanImages sends a scan request to the trivy server for each container image inside the pod and exports the result to prometheus
func (s *Scanner) ScanImages(pod *v1.Pod) ([]*types.Report, error) {

	var reports []*types.Report
	for _, container := range pod.Spec.Containers {
		report, err := s.sendScanRequest(container.Image)
		if err != nil {
			return nil, err
		}
		s.Logger.Infof("trivy report obtained, exporting results")

		image, err := parser.Parse(container.Image)
		if err != nil {
			return nil, err
		}

		for _, result := range report.Results {
			metrics.NewExporter(&container, pod.Namespace, &result, image, report.Metadata.ImageID).PublishReportMetrics()
		}

		reports = append(reports, report)

	}

	s.Logger.Debugf("images were scanned")

	return reports, nil

}

// sendScanRequest sends the image to trivy for scanning and returns the result
func (s *Scanner) sendScanRequest(image string) (*types.Report, error) {

	command := "trivy"
	args := []string{"client", "-f", "json", "--remote", s.RemoteURL, image}

	if s.Insecure {
		args = append(args, "--insecure")
	}

	s.Logger.Debugf("sending scan request for image %s", image)
	s.Logger.Debugf("%s:%v", command, args)

	out, err := exec.RunCommand(command, args...)
	if err != nil {
		return nil, err
	}

	s.Logger.Debugf("image %s has been scanned", image)

	var report types.Report
	err = json.Unmarshal([]byte(out), &report)
	if err != nil {
		return nil, err
	}

	return &report, nil
}
