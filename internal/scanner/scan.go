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

	fmt.Println(pod)

	var containers []v1.ContainerStatus
	for _, init := range pod.Status.InitContainerStatuses {
		containers = append(containers, init)
	}

	for _, eph := range pod.Status.EphemeralContainerStatuses {
		containers = append(containers, eph)
	}

	for _, cs := range pod.Status.ContainerStatuses {
		containers = append(containers, cs)
	}

	fmt.Printf("Got images in pod: %v", containers)

	for _, container := range containers {
		report, err := s.sendScanRequest(container.Image)
		if err != nil {
			return err
		}
		fmt.Println(report)
	}

	fmt.Println("Images were scanned")

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

	fmt.Printf("Sending scan request for image %s", image)

	out, err := exec.Command(command, args...).Output()
	if err != nil {
		fmt.Printf("error exec'ing trivy %s", err.Error())
		return nil, err
	}

	fmt.Printf("Image %s has been scanned", image)

	var report types.Report
	err = json.Unmarshal(out, &report)
	if err != nil {
		return nil, err
	}

	return &report, nil
}
