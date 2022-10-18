package main

import (
	"flag"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	kwhhttp "github.com/slok/kubewebhook/v2/pkg/http"
	kwhlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	kwhprometheus "github.com/slok/kubewebhook/v2/pkg/metrics/prometheus"
	kwhwebhook "github.com/slok/kubewebhook/v2/pkg/webhook"
	kwhvalidating "github.com/slok/kubewebhook/v2/pkg/webhook/validating"
	"github.com/tks98/kube-sentry/internal/scanner"
	v1 "k8s.io/api/core/v1"
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
	metricsAddr string
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
	fl.StringVar(&cfg.metricsAddr, "metrics-addr", ":8081", "The address to start metrics server")
	fl.StringVar(&cfg.trivyAddr, "trivy-addr", "http://127.0.0.1:4954", "The address of the remote trivy server")
	fl.StringVar(&cfg.trivyScheme, "trivy-scheme", "http", "The scheme to reach trivy server (http or https")
	fl.BoolVar(&cfg.insecure, "insecure", false, "Allow insecure server connections to trivy server when using TLS")

	_ = fl.Parse(os.Args[1:])
	return cfg
}

func main() {

	// init logger and parse flags
	logrusLogEntry := logrus.NewEntry(logrus.New())
	logrusLogEntry.Logger.SetLevel(logrus.DebugLevel)
	logger := kwhlogrus.NewLogrus(logrusLogEntry)

	cfg := initFlags()

	// check that trivy is installed
	_, err := exec.LookPath("trivy")
	if err != nil {
		logger.Errorf("trivy is not installed, it is a required dependency")
		os.Exit(1)
	}

	// create a new scanner
	trivyScanner, err := scanner.NewScanner(cfg.trivyAddr, cfg.insecure, logger, cfg.trivyScheme)
	if err != nil {
		logger.Errorf(err.Error())
		os.Exit(1)

	}

	scannerWebhook := &scanner.ImageScanner{
		Logger:  logger,
		Scanner: *trivyScanner,
	}

	// create webhook
	config := kwhvalidating.WebhookConfig{
		ID:        "imageScanner",
		Obj:       &v1.Pod{},
		Validator: scannerWebhook,
		Logger:    logger,
	}

	wh, err := kwhvalidating.NewWebhook(config)
	if err != nil {
		logger.Errorf("error creating webhook: %s", err)
		os.Exit(1)
	}

	// prepare metrics
	reg := prometheus.NewRegistry()
	metricsRec, err := kwhprometheus.NewRecorder(kwhprometheus.RecorderConfig{Registry: reg})
	if err != nil {
		logger.Errorf("could not create Prometheus metrics recorder: %w", err)
		os.Exit(1)
	}

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

	err = <-errCh
	if err != nil {
		logger.Errorf(err.Error())
		os.Exit(1)
	}

}
