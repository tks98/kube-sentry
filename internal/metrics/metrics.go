package metrics

import (
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

func ServePrometheusMetrics(port string) {
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(port, nil)
}
