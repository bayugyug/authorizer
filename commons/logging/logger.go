package logging

import (
	"context"
	"fmt"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/go-chi/chi/middleware"
	log "github.com/sirupsen/logrus"
)

// Init the logger here
func Init(logtype string) {
	log.SetReportCaller(true)
	if strings.EqualFold(logtype, "json") {
		log.SetFormatter(&log.JSONFormatter{
			TimestampFormat: time.RFC3339Nano,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				fun := strings.Split(f.Function, ".")
				return fmt.Sprintf("%s", fun[len(fun)-1]), fmt.Sprintf("%s:%d", path.Base(f.File), f.Line)
			},
		})
	} else {
		log.SetFormatter(&log.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				fun := strings.Split(f.Function, ".")
				return fmt.Sprintf("%s", fun[len(fun)-1]), fmt.Sprintf("%s:%d", path.Base(f.File), f.Line)
			},
		})
	}
	// Only log the DebugLevel severity or above. ( or use WarnLevel ?)
	// log.SetLevel(log.DebugLevel)
}

// GetLoggerCtx ...
func GetLoggerCtx(ctx context.Context) *log.Entry {
	return GetLogger(ctx).WithField(
		XRequestUUIDKey, GetLoggerReqID(ctx),
	)
}

// SetLoggerCtxWithParam ...
func SetLoggerCtxWithParam(ctx context.Context, uuid string) context.Context {
	return context.WithValue(ctx, reqIDKey{}, uuid)
}

// GetLoggerReqID ....
func GetLoggerReqID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	//based on go-chi middleware
	if old := middleware.GetReqID(ctx); old != "" {
		return old
	}
	if reqID, ok := ctx.Value(reqIDKey{}).(string); ok && reqID != "" {
		return reqID
	}
	return ""
}

var (
	// XRequestUUID ...
	XRequestUUID = "X-Correlation-ID"
	// XRequestUUIDKey ...
	XRequestUUIDKey = "correlation_id"
	// G is an alias for GetLogger.
	//
	// We may want to define this locally to a package to get package tagged log
	// messages.
	G = GetLogger

	// L is an alias for the standard logger.
	L = log.NewEntry(log.StandardLogger())
)

type (
	loggerKey struct{}
	reqIDKey  struct{}
)

// WithLogger returns a new context with the provided logger. Use in
// combination with logger.WithField(s) for great effect.
func WithLogger(ctx context.Context, logger *log.Entry) context.Context {
	return context.WithValue(ctx, loggerKey{}, logger)
}

// GetLogger retrieves the current logger from the context. If no logger is
// available, the default logger is returned.
func GetLogger(ctx context.Context) *log.Entry {
	if ctx == nil {
		return L
	}
	logger := ctx.Value(loggerKey{})
	if logger == nil {
		return L
	}
	return logger.(*log.Entry)
}

func init() {
	//sync the headers of the go-chi middleware for req-id
	middleware.RequestIDHeader = XRequestUUID
}
