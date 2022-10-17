package scanner

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/types"
	kwhlog "github.com/slok/kubewebhook/v2/pkg/log"
	v1 "k8s.io/api/core/v1"
	"os/exec"
)

type Scanner struct {
	RemoteURL string
	Insecure  bool
	Logger    kwhlog.Logger
}

func NewScanner(remoteURL string, insecure bool, logger kwhlog.Logger) (*Scanner, error) {
	if remoteURL == "" {
		return nil, fmt.Errorf("remote url must be set for trivy scanner")
	}

	return &Scanner{
		RemoteURL: remoteURL,
		Insecure:  insecure,
		Logger:    logger,
	}, nil
}

func (s *Scanner) ScanImages(pod *v1.Pod) error {

	s.Logger.Infof("pod %s", pod)

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

	s.Logger.Infof("Got images in pod: %v", containers)

	for _, container := range containers {
		report, err := s.sendScanRequest(container.Image)
		if err != nil {
			return err
		}
		s.Logger.Infof("report %v", report)
	}

	s.Logger.Infof("Images were scanned")

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

	s.Logger.Infof("Sending scan request for image %s", image)

	out, err := exec.Command(command, args...).Output()
	if err != nil {
		s.Logger.Infof("error exec'ing trivy %s", err.Error())
		return nil, err
	}

	s.Logger.Infof("Image %s has been scanned", image)

	var report types.Report
	err = json.Unmarshal(out, &report)
	if err != nil {
		return nil, err
	}

	return &report, nil
}
