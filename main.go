package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	kwhhttp "github.com/slok/kubewebhook/v2/pkg/http"
	kwhlog "github.com/slok/kubewebhook/v2/pkg/log"
	kwhlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
	kwhvalidating "github.com/slok/kubewebhook/v2/pkg/webhook/validating"
	"github.com/tks98/kube-sentry/internal/scanner"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"net/http"
	"os"
	"os/exec"
)

// send scan request to remote trivy-server
// get and parse scan results
// store scan results in database
// export results as prom metrics
// write tool that can extract scan results from database in readable format

// send scan request to remote trivy-server
// get and parse scan results
// store scan results in database
// export results as prom metrics
// write tool that can extract scan results from database in readable format

type config struct {
	certFile    string
	keyFile     string
	addr        string
	trivyAddr   string
	trivyScheme string
	insecure    bool
}

func initFlags() *config {
	cfg := &config{}

	fl := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fl.StringVar(&cfg.certFile, "tls-cert-file", "", "TLS certificate file")
	fl.StringVar(&cfg.keyFile, "tls-key-file", "", "TLS key file")
	fl.StringVar(&cfg.addr, "listen-addr", ":8080", "The address to start the server")
	fl.StringVar(&cfg.trivyAddr, "trivy-addr", "http://127.0.0.1:4954", "The address of the remote trivy server")
	fl.StringVar(&cfg.trivyScheme, "trivy-scheme", "http", "The scheme to reach trivy server (http or https")
	fl.BoolVar(&cfg.insecure, "insecure", false, "Allow insecure server connections to trivy server when using TLS")

	_ = fl.Parse(os.Args[1:])
	return cfg
}

type imageScanner struct {
	logger  kwhlog.Logger
	scanner scanner.Scanner
}

func (is *imageScanner) Validate(_ context.Context, _ *kwhmodel.AdmissionReview, obj metav1.Object) (*kwhvalidating.ValidatorResult, error) {
	pod, ok := obj.(*v1.Pod)
	if !ok {
		return nil, fmt.Errorf("not a pod")
	}

	is.logger.Infof("pod %s is valid", pod.Name)

	err := is.scanner.ScanImages(pod)
	if err != nil {
		is.logger.Errorf(err.Error())
		return nil, err
	}

	is.logger.Infof("%s images have been scanned", pod.Name)

	return &kwhvalidating.ValidatorResult{
		Valid:   true,
		Message: "pod images have been scanned",
	}, nil
}

func main() {

	logrusLogEntry := logrus.NewEntry(logrus.New())
	logrusLogEntry.Logger.SetLevel(logrus.DebugLevel)
	logger := kwhlogrus.NewLogrus(logrusLogEntry)

	cfg := initFlags()

	_, err := exec.LookPath("trivy")
	if err != nil {
		logger.Errorf("trivy is not installed, it is a required dependency")
		os.Exit(1)
	}

	trivyScanner, err := scanner.NewScanner(cfg.trivyAddr, cfg.insecure, logger, cfg.trivyScheme)
	if err != nil {
		logger.Errorf(err.Error())
		os.Exit(1)

	}
	vl := &imageScanner{
		logger:  logger,
		scanner: *trivyScanner,
	}

	config := kwhvalidating.WebhookConfig{
		ID:        "imageScanner",
		Obj:       &v1.Pod{},
		Validator: vl,
		Logger:    logger,
	}
	wh, err := kwhvalidating.NewWebhook(config)
	if err != nil {
		logger.Errorf("error creating webhook: %s", err)
		os.Exit(1)
	}

	// Serve the webhook.
	logger.Infof("Listening on %s", cfg.addr)
	err = http.ListenAndServeTLS(cfg.addr, cfg.certFile, cfg.keyFile, kwhhttp.MustHandlerFor(kwhhttp.HandlerConfig{
		Webhook: wh,
		Logger:  logger,
	}))
	if err != nil {
		logger.Errorf("error serving webhook: %s", err)
		os.Exit(1)
	}
}
