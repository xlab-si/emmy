package log

import "github.com/op/go-logging"

var clientModule = "client"
var serverModule = "server"

var longFormat = logging.MustStringFormatter(
	`%{color}[%{module}] %{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

var shortFormat = logging.MustStringFormatter(
	`%{color}%{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

// Expose two per-package loggers, one for client side, one for server side
var ClientLogger, ServerLogger *Logger

// Logger is a convenience wrapper struct that embeds go-logging logger.
// We use it for easier configuration of log levels
type Logger struct {
	*logging.Logger
}

func newLogger(module string) *Logger {
	return &Logger{
		logging.MustGetLogger(module),
	}
}

// init instantiates and configures client and server loggers with the default format and
// log level.
func init() {
	ClientLogger = newLogger(clientModule)
	ServerLogger = newLogger(serverModule)
	ClientLogger.SetLevel("info")
	ServerLogger.SetLevel("info")
	logging.SetFormatter(longFormat)
}

// SetLevel sets the log level for the given logger. In case of an invalid log level argument,
// it propagates the error detected by go-logging's package logging
func (logger *Logger) SetLevel(level string) error {
	// obtain logging.Level type from a string argument representing log level
	levelInt, err := logging.LogLevel(level)
	if err != nil {
		return err
	}

	logging.SetLevel(levelInt, logger.Module)
	return nil
}

// TurnOff sets the log level of server and client loggers to -1, causing logs not to
// be printed to stdout. This is useful to avoid otherwise verbose logging during benchmarks
// It would be better to use Logger's SetLevel function, but it accepts only a supported set of
// string argument, so the '-1' log level cannot be correctly represented
func TurnOff() {
	logging.SetLevel(-1, ClientLogger.Module)
	logging.SetLevel(-1, ServerLogger.Module)
}
