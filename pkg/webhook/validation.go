package webhook

import (
	"strconv"
	"strings"
)

func InitRejectionCriteria(forbiddenCVEs string, numAllowedCVEs string, numCriticalCVEs string) (*RejectionCriteria, error) {

	var rejectionCriteria RejectionCriteria

	rejectionCriteria.Disabled = false
	if forbiddenCVEs != "" {
		rejectionCriteria.ForbiddenCVEs = &ForbiddenCVEs{CVEs: strings.Split(forbiddenCVEs, ",")}
	}
	if numCriticalCVEs != "" {
		numCritical, err := strconv.Atoi(numCriticalCVEs)
		if err != nil {
			return nil, err
		}
		rejectionCriteria.NumCriticalCVEs = &NumCriticalCVEs{CriticalCVEs: numCritical}
	}

	if numAllowedCVEs != "" {
		numAllowed, err := strconv.Atoi(numAllowedCVEs)
		if err != nil {
			return nil, err
		}
		rejectionCriteria.NumAllowedCVEs = &NumAllowedCVEs{AllowedCVEs: numAllowed}

	}

	return &rejectionCriteria, nil

}
