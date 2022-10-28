package logging

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/slok/kubewebhook/v2/pkg/log"
	kwhlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	"strings"
)

func NewLogger(level string) (log.Logger, error) {

	// init logging and parse flags
	logrusLogEntry := logrus.NewEntry(logrus.New())

	var logLevel logrus.Level
	switch strings.ToLower(level) {
	case "info":
		logLevel = logrus.InfoLevel
	case "debug":
		logLevel = logrus.DebugLevel
	default:
		return nil, fmt.Errorf("logging level %s not supported", level)
	}

	logrusLogEntry.Logger.SetLevel(logLevel)
	logger := kwhlogrus.NewLogrus(logrusLogEntry)
	return logger, nil

}
