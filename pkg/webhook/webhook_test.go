package webhook

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/tks98/kube-sentry/pkg/exec"
	"github.com/tks98/kube-sentry/pkg/logging"
	"github.com/tks98/kube-sentry/pkg/scanner"
	v1 "k8s.io/api/core/v1"
	"testing"
)

// TestValidationResult tests that the scanning and validation logic works as expected with a known image and set rejection parameters
func TestValidationResult(t *testing.T) {

	// start trivy server
	go func() {
		command := "trivy"
		args := []string{"server", "--listen", "0.0.0.0:8080"}
		_, err := exec.RunCommand(command, args...)
		if err != nil {
			t.Errorf(err.Error())
		}
	}()

	t.Log("trivy server started")

	// set image validation rejection criteria
	forbiddenCVEs := "CVE-2020-36309, CVE-2013-0337"
	numCriticalCVEs := "10"
	numAllowedCVEs := "30"

	rejectionCriteria, err := InitRejectionCriteria(forbiddenCVEs, numCriticalCVEs, numAllowedCVEs)
	if err != nil {
		t.Error(err)
	}

	// create logger
	logger, err := logging.NewLogger("debug")
	if err != nil {
		t.Error(err)
	}

	// create scanner
	scanner, err := scanner.NewScanner("0.0.0.0:8080", false, logger, "http")
	if err != nil {
		t.Error(err)
	}

	// create image scanner type
	var is ImageScanner
	is.RejectionCriteria = *rejectionCriteria
	is.Scanner = *scanner
	is.Logger = logger

	// create mock container
	container := v1.Container{
		Name:  "nginx",
		Image: "nginx:1.14.2",
	}

	// send scan request
	var results []*types.Report
	result, err := is.Scanner.SendScanRequest(container.Image)
	if err != nil {
		t.Error(err)
	}

	t.Logf("image %s scanned", container.Image)

	// determine if scan results are expected
	results = append(results, result)
	validationResult := is.GetValidatorResult(results)
	if validationResult.Valid != false {
		t.Errorf("validation result: got %v, wanted %v", validationResult.Valid, false)
	}
}
