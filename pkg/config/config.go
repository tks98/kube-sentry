package config

import (
	"flag"
	"os"
	"strings"
)

// config stores the application's configuration state
type config struct {
	CertFile        string
	KeyFile         string
	LogLevel        string
	Addr            string
	MetricsAddr     string
	TrivyAddr       string
	TrivyScheme     string
	Insecure        bool
	MetricsLabels   string
	ForbiddenCVEs   string
	NumAllowedCVEs  string
	NumCriticalCVEs string
	SentryMode      bool
}

// ParseFlags parses the application arguments and creates a config type
func ParseFlags() *config {
	cfg := &config{}

	fl := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fl.StringVar(&cfg.CertFile, "tls-cert-file", "", "TLS certificate file")
	fl.StringVar(&cfg.KeyFile, "tls-key-file", "", "TLS key file")
	fl.StringVar(&cfg.LogLevel, "log-level", "info", "Specifies the logging level (info or debug")
	fl.StringVar(&cfg.Addr, "listen-addr", ":8080", "The address to start the server")
	fl.StringVar(&cfg.MetricsAddr, "metrics-addr", ":8081", "The address to start metrics server")
	fl.StringVar(&cfg.TrivyAddr, "trivy-addr", "http://127.0.0.1:4954", "The address of the remote trivy server")
	fl.StringVar(&cfg.TrivyScheme, "trivy-scheme", "http", "The scheme to reach trivy server (http or https")
	fl.BoolVar(&cfg.Insecure, "insecure", false, "Allow insecure connections to container registries")
	fl.StringVar(&cfg.MetricsLabels, "metrics-labels", "", "Specifies the metrics labels to export. If not given, will export all")
	fl.BoolVar(&cfg.SentryMode, "sentry-mode", false, "Enables or disables rejecting pods based on trivy scan results")
	fl.StringVar(&cfg.ForbiddenCVEs, "forbidden-cves", "", "Specifies which CVEs in images causes pod validation to fail")
	fl.StringVar(&cfg.NumCriticalCVEs, "num-critical-cves", "", "Specifies max number of critical CVEs pod images can have")
	fl.StringVar(&cfg.NumAllowedCVEs, "num-allowed-cves", "", "Specifies max number of CVEs pod images can have")

	_ = fl.Parse(os.Args[1:])

	// clean up args
	cfg.ForbiddenCVEs = strings.Trim(cfg.ForbiddenCVEs, "\"")
	cfg.ForbiddenCVEs = strings.Trim(cfg.ForbiddenCVEs, "\n")
	cfg.ForbiddenCVEs = strings.Trim(cfg.ForbiddenCVEs, "")
	cfg.ForbiddenCVEs = strings.Trim(cfg.ForbiddenCVEs, " ")
	cfg.MetricsLabels = strings.Trim(cfg.MetricsLabels, "\"")
	cfg.MetricsLabels = strings.Trim(cfg.MetricsLabels, "\n")
	cfg.MetricsLabels = strings.Trim(cfg.MetricsLabels, "")
	cfg.MetricsLabels = strings.Trim(cfg.MetricsLabels, " ")
	return cfg
}
