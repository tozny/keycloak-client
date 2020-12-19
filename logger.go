package keycloak

import (
	"net/http"
	"time"

	"gopkg.in/h2non/gentleman.v2/context"
	"gopkg.in/h2non/gentleman.v2/plugin"
)

// RequestLogger wraps indicates a logger with a Debugf method
type RequestLogger interface {
	Debugf(string, ...interface{})
}

type loggingTransport struct {
	writer RequestLogger
	parent http.RoundTripper
}

func newLoggingRoundTripper(logger RequestLogger, parent http.RoundTripper) http.RoundTripper {
	return &loggingTransport{
		writer: logger,
		parent: parent,
	}
}

func (lt *loggingTransport) parentTransport() http.RoundTripper {
	if lt.parent == nil {
		return http.DefaultTransport
	}
	return lt.parent
}

func (lt *loggingTransport) CancelRequest(req *http.Request) {
	type canceler interface {
		CancelRequest(*http.Request)
	}
	if cr, ok := lt.parentTransport().(canceler); ok {
		cr.CancelRequest(req)
	}
}

func (lt *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	startTime := time.Now()
	at := req.Header.Get("Date")
	if at == "" {
		at = startTime.String()
	}
	resp, err := lt.parentTransport().RoundTrip(req)
	lt.writer.Debugf("%s request to %s at %s took %s", req.Method, req.URL, at, time.Now().Sub(startTime))
	return resp, err
}

func loggerPlugin(logger RequestLogger) plugin.Plugin {
	return plugin.NewRequestPlugin(func(c *context.Context, h context.Handler) {
		c.Client.Transport = newLoggingRoundTripper(logger, nil)
		h.Next(c)
	})
}
