package scanner

import (
	"context"
	"fmt"
	kwhlog "github.com/slok/kubewebhook/v2/pkg/log"
	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
	kwhvalidating "github.com/slok/kubewebhook/v2/pkg/webhook/validating"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ImageScanner struct {
	Logger  kwhlog.Logger
	Scanner Scanner
}

func (is *ImageScanner) Validate(_ context.Context, _ *kwhmodel.AdmissionReview, obj metav1.Object) (*kwhvalidating.ValidatorResult, error) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return nil, fmt.Errorf("not a pod")
	}

	is.Logger.Infof("pod %s is valid", pod.Name)

	err := is.Scanner.ScanImages(pod)
	if err != nil {
		is.Logger.Errorf(err.Error())
		return nil, err
	}

	is.Logger.Infof("%s images have been scanned", pod.Name)

	return &kwhvalidating.ValidatorResult{
		Valid:   true,
		Message: "pod images have been scanned",
	}, nil
}
