package scanner

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/types"
	v1 "k8s.io/api/core/v1"
	"os/exec"
)

type Scanner struct {
	RemoteURL string
	Insecure  bool
}

func NewScanner(remoteURL string, insecure bool) (*Scanner, error) {
	if remoteURL == "" {
		return nil, fmt.Errorf("remote url must be set for trivy scanner")
	}

	return &Scanner{
		RemoteURL: remoteURL,
		Insecure:  insecure,
	}, nil
}

func (s *Scanner) ScanImages(pod *v1.Pod) error {

	var containers []v1.ContainerStatus
	for _, init := range pod.Status.InitContainerStatuses {
		for _, eph := range pod.Status.EphemeralContainerStatuses {
			for _, cs := range pod.Status.ContainerStatuses {
				containers = append(containers, init, eph, cs)
			}
		}
	}

	for _, container := range containers {
		report, err := s.sendScanRequest(container.Image)
		if err != nil {
			return err
		}
		fmt.Println(report)
	}

	// export report info as prom metrics
	// save report into to database

	return nil

}

func (s *Scanner) sendScanRequest(image string) (*types.Report, error) {

	command := "trivy"
	args := []string{"client", "-f", "json", "--remote", s.RemoteURL, image}

	if s.Insecure {
		args = append(args, "--insecure")
	}

	cmd := exec.Command(command, args...)
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var report types.Report
	err = json.Unmarshal(out, &report)
	if err != nil {
		return nil, err
	}

	return &report, nil
}
