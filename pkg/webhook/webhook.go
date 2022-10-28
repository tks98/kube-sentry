package webhook

import (
	"context"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/types"
	kwhlog "github.com/slok/kubewebhook/v2/pkg/log"
	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
	kwhvalidating "github.com/slok/kubewebhook/v2/pkg/webhook/validating"
	"github.com/tks98/kube-sentry/pkg/scanner"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"
	"strings"
)

type ForbiddenCVEs struct {
	CVEs []string // CVE id's "CVE-2021-44228, CVE-2022-22965, CVE‑2021‑25741"
}

type NumAllowedCVEs struct {
	AllowedCVEs int
}

type NumCriticalCVEs struct {
	CriticalCVEs int
}

// RejectionCriteria allows users to define when to reject a pod from starting based on scan results its image(s)
type RejectionCriteria struct {
	ForbiddenCVEs   *ForbiddenCVEs   // CVE id's "CVE-2021-44228, CVE-2022-22965, CVE‑2021‑25741"
	NumAllowedCVEs  *NumAllowedCVEs  // Rejects pod if total number of CVEs in all container images goes above this number
	NumCriticalCVEs *NumCriticalCVEs // Rejects pod if total number of critical CVEs in all container images goes above this number
	Disabled        bool             // Never rejects pods
}

type ImageScanner struct {
	Logger            kwhlog.Logger
	Scanner           scanner.Scanner
	RejectionCriteria RejectionCriteria
}

// Validate is the function called by the admission controller when, in our case, pods are created or updated
// The images for each container are sent to the trivy scanner and the results are exposed as prometheus metrics
func (is *ImageScanner) Validate(_ context.Context, _ *kwhmodel.AdmissionReview, obj metav1.Object) (*kwhvalidating.ValidatorResult, error) {

	// verify the pod is valid
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return nil, fmt.Errorf("not a pod")
	}

	is.Logger.Infof("pod %s is valid", pod.Name)

	// scan container images and export results
	results, err := is.Scanner.ScanImages(pod)
	if err != nil {
		is.Logger.Errorf(err.Error())
		return nil, err
	}

	is.Logger.Infof("%s images have been scanned", pod.Name)

	// check if scan report for pod images meets validation criteria defined by user
	return is.getValidatorResult(results), nil
}

// getValidatorResult checks if the trivy scan results for all pod container images violated any of the rules defined by the user in RejectionCriteria
func (is *ImageScanner) getValidatorResult(results []*types.Report) *kwhvalidating.ValidatorResult {

	var rulesViolated []string

	var allowed = &kwhvalidating.ValidatorResult{
		Valid:   true,
		Message: "pod images have been scanned",
	}

	// validation is disabled
	if is.RejectionCriteria.Disabled {
		return allowed
	}

	is.Logger.Debugf("Checking if report passes validation")

	// check if total number of CVEs is over allowed value, if enabled
	if is.RejectionCriteria.NumAllowedCVEs != nil {

		is.Logger.Debugf("checking number of CVEs")

		var total int
		for _, report := range results {
			for _, result := range report.Results {
				total += len(result.Vulnerabilities)
			}
		}

		if total > is.RejectionCriteria.NumAllowedCVEs.AllowedCVEs {
			is.Logger.Debugf("too many CVEs")
			rulesViolated = append(rulesViolated, "pod container images contain too many total vulnerabilities ")
		}
	}

	// check if total number of critical CVEs is over allowed value, if enabled
	if is.RejectionCriteria.NumCriticalCVEs != nil {

		is.Logger.Debugf("checking number of critical CVEs")

		var totalCriticalCVEs int
		for _, report := range results {
			for _, result := range report.Results {
				for _, vuln := range result.Vulnerabilities {

					// check if CVE is critical
					if vuln.Severity == "CRITICAL" {
						totalCriticalCVEs += 1
					}
				}
			}
		}

		if totalCriticalCVEs > is.RejectionCriteria.NumCriticalCVEs.CriticalCVEs {
			is.Logger.Debugf("too many critical CVEs")
			rulesViolated = append(rulesViolated, "pod container images contain too many critical vulnerabilities")
		}
	}

	// check if any of the CVEs are part of the forbidden CVEs
	if is.RejectionCriteria.ForbiddenCVEs != nil {

		is.Logger.Debugf("checking for forbidden CVEs")
		for _, report := range results {
			for _, result := range report.Results {
				for _, vuln := range result.Vulnerabilities {
					if slices.Contains(is.RejectionCriteria.ForbiddenCVEs.CVEs, vuln.VulnerabilityID) {
						is.Logger.Infof("forbidden CVE found %s", vuln.VulnerabilityID)
						msg := fmt.Sprintf("pod container image %s contains forbidden CVE %s", result.Target, vuln.VulnerabilityID)
						rulesViolated = append(rulesViolated, msg)
					}

				}
			}
		}
	}

	// if any rules were violated, reject pod and include which ones were violated
	if len(rulesViolated) != 0 {
		return &kwhvalidating.ValidatorResult{
			Valid:   false,
			Message: strings.Join(rulesViolated[:], ","),
		}
	}

	is.Logger.Debugf("validation passed")
	return allowed

}

func (is *ImageScanner) checkForbidden(target string, cveID string) *kwhvalidating.ValidatorResult {

	// check if CVE is in list of forbidden CVEs
	if slices.Contains(is.RejectionCriteria.ForbiddenCVEs.CVEs, cveID) {
		msg := fmt.Sprintf("pod container image %s contains forbidden CVE %s", target, cveID)
		return &kwhvalidating.ValidatorResult{
			Valid:   false,
			Message: msg,
		}
	}

	return nil

}
