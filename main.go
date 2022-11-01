package main

import (
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	kwhhttp "github.com/slok/kubewebhook/v2/pkg/http"
	kwhprometheus "github.com/slok/kubewebhook/v2/pkg/metrics/prometheus"
	kwhwebhook "github.com/slok/kubewebhook/v2/pkg/webhook"
	kwhvalidating "github.com/slok/kubewebhook/v2/pkg/webhook/validating"
	"github.com/tks98/kube-sentry/pkg/config"
	"github.com/tks98/kube-sentry/pkg/logging"
	"github.com/tks98/kube-sentry/pkg/metrics"
	"github.com/tks98/kube-sentry/pkg/scanner"
	"github.com/tks98/kube-sentry/pkg/webhook"
	v1 "k8s.io/api/core/v1"
	"net/http"
	"os"
	"os/exec"
)

func main() {

	// parse program arguments into config type
	cfg := config.ParseFlags()

	// init logging and parse flags
	logger, err := logging.NewLogger(cfg.LogLevel)
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
	trivyScanner, err := scanner.NewScanner(cfg.TrivyAddr, cfg.Insecure, logger, cfg.TrivyScheme)
	if err != nil {
		logger.Errorf(err.Error())
		os.Exit(1)

	}

	// determine which criteria result in kube-sentry blocking pod creation
	var rejectionCriteria *webhook.RejectionCriteria
	if cfg.SentryMode {
		rejectionCriteria, err = webhook.InitRejectionCriteria(cfg.ForbiddenCVEs, cfg.NumCriticalCVEs, cfg.NumAllowedCVEs)
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
	metrics.RegisterVulnerabilityCollector(reg, cfg.MetricsLabels)

	errCh := make(chan error)

	// serve the webhook
	go func() {
		logger.Infof("Listening on %s", cfg.Addr)
		err = http.ListenAndServeTLS(cfg.Addr, cfg.CertFile, cfg.KeyFile, kwhhttp.MustHandlerFor(kwhhttp.HandlerConfig{
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
		logger.Infof("Listening metrics on %s", cfg.MetricsAddr)
		err = http.ListenAndServe(cfg.MetricsAddr, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
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
