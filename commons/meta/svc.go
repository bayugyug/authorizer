package meta

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/bayugyug/authorizer/commons/logging"
	log "github.com/sirupsen/logrus"
)

var (
	// RFC3339 ...
	RFC3339 = "2006-01-02T15:04:05.000Z07:00"
	// Verbose ...
	Verbose = true
	// LogPrefix ...
	LogPrefix = `External request calls`
	// Prefix ...
	Prefix = `meta_ext_req_logs`
)

// OptArgs options ...
type OptArgs func(*ReqTiming)

// WithPrefix ...
func WithPrefix(param string) OptArgs {
	return func(args *ReqTiming) {
		args.Prefix = param
	}
}

// WithVerbose ...
func WithVerbose(param bool) OptArgs {
	return func(args *ReqTiming) {
		args.Debug = param
	}
}

// ReqTiming ...
type ReqTiming struct {
	Start   string    `json:"start,omitempty"`
	End     string    `json:"end,omitempty"`
	Elapsed int64     `json:"elapsed,omitempty"`
	Caller  *Caller   `json:"caller,omitempty"`
	Now     time.Time `json:"-"`
	Debug   bool      `json:"-"`
	Prefix  string    `json:"-"`
}

// Caller ...
type Caller struct {
	File string `json:"file,omitempty"`
	Func string `json:"func,omitempty"`
}

// New ...
func New(args ...OptArgs) *ReqTiming {
	logging.Init(`json`)

	// start ts
	ts := time.Now().Local()

	// default
	svc := &ReqTiming{
		Start:  ts.Format(RFC3339),
		Now:    ts,
		Prefix: LogPrefix,
		Debug:  Verbose,
	}

	//chk the passed params
	for _, settings := range args {
		settings(svc)
	}

	// good :-)
	return svc
}

// Done ..
func (s *ReqTiming) Done() {
	if s == nil {
		return
	}
	// add more info
	s.End = time.Now().Local().Format(RFC3339)
	s.Elapsed = time.Since(s.Now).Milliseconds()
	if s.Caller == nil {
		name, line := logging.GetLogFrame(2)
		s.Caller = &Caller{
			File: line,
			Func: name,
		}
	}
	// show it
	if s.Debug {
		log.WithFields(
			log.Fields{
				Prefix: map[string]interface{}{
					"start":   s.Start,
					"end":     s.End,
					"elapsed": s.Elapsed,
					"caller":  s.Caller,
				},
			}).Println(LogPrefix)
	}
}

// String ..
func (s *ReqTiming) String() string {
	if s == nil {
		return ""
	}
	b, _ := json.Marshal(s)
	return fmt.Sprintf("%s: %s", s.Prefix, string(b))
}
