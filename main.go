package main

import (
	"flag"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	kwhhttp "github.com/slok/kubewebhook/v2/pkg/http"
	kwhprometheus "github.com/slok/kubewebhook/v2/pkg/metrics/prometheus"
	kwhwebhook "github.com/slok/kubewebhook/v2/pkg/webhook"
	kwhvalidating "github.com/slok/kubewebhook/v2/pkg/webhook/validating"
	"github.com/tks98/kube-sentry/pkg/logging"
	"github.com/tks98/kube-sentry/pkg/metrics"
	"github.com/tks98/kube-sentry/pkg/scanner"
	"github.com/tks98/kube-sentry/pkg/webhook"
	v1 "k8s.io/api/core/v1"
	"net/http"
	"os"
	"os/exec"
	"strings"
)

// config stores the application's configuration state
type config struct {
	certFile        string
	keyFile         string
	logLevel        string
	addr            string
	metricsAddr     string
	trivyAddr       string
	trivyScheme     string
	insecure        bool
	metricsLabels   string
	forbiddenCVEs   string
	numAllowedCVEs  string
	numCriticalCVEs string
	sentryMode      bool
}

// initFlags() parses the application arguments and creates a config type
func initFlags() *config {
	cfg := &config{}

	fl := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fl.StringVar(&cfg.certFile, "tls-cert-file", "", "TLS certificate file")
	fl.StringVar(&cfg.keyFile, "tls-key-file", "", "TLS key file")
	fl.StringVar(&cfg.logLevel, "log-level", "info", "Specifies the logging level (info or debug")
	fl.StringVar(&cfg.addr, "listen-addr", ":8080", "The address to start the server")
	fl.StringVar(&cfg.metricsAddr, "metrics-addr", ":8081", "The address to start metrics server")
	fl.StringVar(&cfg.trivyAddr, "trivy-addr", "http://127.0.0.1:4954", "The address of the remote trivy server")
	fl.StringVar(&cfg.trivyScheme, "trivy-scheme", "http", "The scheme to reach trivy server (http or https")
	fl.BoolVar(&cfg.insecure, "insecure", false, "Allow insecure server connections to trivy server when using TLS")
	fl.StringVar(&cfg.metricsLabels, "metrics-labels", "", "Specifies the metrics labels to export. If not given, will export all")
	fl.BoolVar(&cfg.sentryMode, "sentry-mode", false, "Enables or disables rejecting pods based on trivy scan results")
	fl.StringVar(&cfg.forbiddenCVEs, "forbidden-cves", "", "Specifies which CVEs in images causes pod validation to fail")
	fl.StringVar(&cfg.numCriticalCVEs, "num-critical-cves", "", "Specifies max number of critical CVEs pod images can have")
	fl.StringVar(&cfg.numAllowedCVEs, "num-allowed-cves", "", "Specifies max number of CVEs pod images can have")

	_ = fl.Parse(os.Args[1:])

	// clean up args
	cfg.forbiddenCVEs = strings.Trim(cfg.forbiddenCVEs, "\"")
	cfg.forbiddenCVEs = strings.Trim(cfg.forbiddenCVEs, "\n")
	cfg.forbiddenCVEs = strings.Trim(cfg.forbiddenCVEs, "")
	cfg.forbiddenCVEs = strings.Trim(cfg.forbiddenCVEs, " ")
	cfg.metricsLabels = strings.Trim(cfg.metricsLabels, "\"")
	cfg.metricsLabels = strings.Trim(cfg.metricsLabels, "\n")
	cfg.metricsLabels = strings.Trim(cfg.metricsLabels, "")
	cfg.metricsLabels = strings.Trim(cfg.metricsLabels, " ")
	return cfg
}

func main() {

	// parse config and clean args
	cfg := initFlags()

	// init logging and parse flags
	logger, err := logging.NewLogger(cfg.logLevel)
	if err != nil {
		fmt.Printf(err.Error())
		os.Exit(1)
	}

	// check that trivy is installed
	_, err = exec.LookPath("trivy")
	if err != nil {
		logger.Errorf("trivy is not installed, it is a required dependency")
		os.Exit(1)
	}

	// create a new trivy scanner
	trivyScanner, err := scanner.NewScanner(cfg.trivyAddr, cfg.insecure, logger, cfg.trivyScheme)
	if err != nil {
		logger.Errorf(err.Error())
		os.Exit(1)

	}

	// determine which criteria result in kube-sentry blocking pod creation
	var rejectionCriteria *webhook.RejectionCriteria
	if cfg.sentryMode {
		rejectionCriteria, err = webhook.InitRejectionCriteria(cfg.forbiddenCVEs, cfg.numCriticalCVEs, cfg.numAllowedCVEs)
		if err != nil {
			logger.Errorf(err.Error())
			os.Exit(1)
		}
	}

	// create the scanner webhook validator
	scannerWebhook := &webhook.ImageScanner{
		Logger:            logger,
		Scanner:           *trivyScanner,
		RejectionCriteria: *rejectionCriteria,
	}

	// create webhook
	config := kwhvalidating.WebhookConfig{
		ID:        "imageScanner",
		Obj:       &v1.Pod{},
		Validator: scannerWebhook,
		Logger:    logger,
	}

	// register the webhook
	wh, err := kwhvalidating.NewWebhook(config)
	if err != nil {
		logger.Errorf("error creating webhook: %s", err)
		os.Exit(1)
	}

	// prepare prometheus metrics
	reg := prometheus.NewRegistry()
	metricsRec, err := kwhprometheus.NewRecorder(kwhprometheus.RecorderConfig{Registry: reg})
	if err != nil {
		logger.Errorf("could not create Prometheus metrics recorder: %w", err)
		os.Exit(1)
	}

	// register the vulnerabilityInfo collector for exporting scan results
	metrics.RegisterVulnerabilityCollector(reg, cfg.metricsLabels)

	errCh := make(chan error)

	// serve the webhook
	go func() {
		logger.Infof("Listening on %s", cfg.addr)
		err = http.ListenAndServeTLS(cfg.addr, cfg.certFile, cfg.keyFile, kwhhttp.MustHandlerFor(kwhhttp.HandlerConfig{
			Webhook: kwhwebhook.NewMeasuredWebhook(metricsRec, wh),
			Logger:  logger,
		}))
		if err != nil {
			errCh <- fmt.Errorf("error serving webhook: %s", err)
		}
		errCh <- nil
	}()

	// serve metrics.
	go func() {
		logger.Infof("Listening metrics on %s", cfg.metricsAddr)
		err = http.ListenAndServe(cfg.metricsAddr, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
		if err != nil {
			errCh <- fmt.Errorf("error serving webhook metrics: %w", err)
		}
		errCh <- nil
	}()

	// listen for errors
	err = <-errCh
	if err != nil {
		logger.Errorf(err.Error())
		os.Exit(1)
	}

}
