package log

import (
	"context"
	stdlog "log"
	"os"

	console "github.com/mattn/go-isatty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type (
	Logger  = zerolog.Logger
	Context = zerolog.Context
	Event   = *zerolog.Event
)

var DefaultLogger *Logger

var (
	DebugLevel = zerolog.DebugLevel
	InfoLevel  = zerolog.InfoLevel
	WarnLevel  = zerolog.WarnLevel
	ErrorLevel = zerolog.ErrorLevel
	FatalLevel = zerolog.FatalLevel
	PanicLevel = zerolog.PanicLevel

	SetLevel = zerolog.SetGlobalLevel
)

var (
	Err       = log.Err
	Trace     = log.Trace
	Debug     = log.Debug
	Info      = log.Info
	Warn      = log.Warn
	Error     = log.Error
	Fatal     = log.Fatal
	Panic     = log.Panic
	Log       = log.Log
	WithLevel = log.WithLevel
	Print     = log.Print
	Printf    = log.Printf
)

func init() {
	log.Logger = log.Logger.Output(zerolog.ConsoleWriter{
		Out:     os.Stderr,
		NoColor: !console.IsTerminal(os.Stderr.Fd()),
	})

	zerolog.DefaultContextLogger = &log.Logger
	DefaultLogger = &log.Logger

	stdlog.SetFlags(0)
	stdlog.SetOutput(log.Logger)
}

func With() Context {
	return log.Logger.With()
}

func WithContext(ctx context.Context) context.Context {
	return log.Logger.WithContext(ctx)
}

func Ctx(ctx context.Context) *Logger {
	return zerolog.Ctx(ctx)
}
