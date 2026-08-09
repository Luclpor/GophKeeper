package server

import (
	"net/http"
	"time"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	status       int
	bytesWritten int
}

func (w *loggingResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *loggingResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	written, err := w.ResponseWriter.Write(data)
	w.bytesWritten += written
	return written, err
}

func (a *App) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startedAt := time.Now()
		wrapped := &loggingResponseWriter{ResponseWriter: w}

		next.ServeHTTP(wrapped, r)

		status := wrapped.status
		if status == 0 {
			status = http.StatusOK
		}

		level := "info"
		if status >= http.StatusInternalServerError {
			level = "error"
		}

		a.logger.Printf(
			"level=%s msg=%q method=%s path=%q status=%d bytes=%d duration=%s remote_addr=%q request_id=%q user_agent=%q",
			level,
			"http request completed",
			r.Method,
			r.URL.Path,
			status,
			wrapped.bytesWritten,
			time.Since(startedAt),
			r.RemoteAddr,
			requestIDFromContext(r.Context()),
			r.UserAgent(),
		)
	})
}
