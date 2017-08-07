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

var ClientLogger, ServerLogger *logging.Logger

func init() {
	ClientLogger = logging.MustGetLogger("client")
	ServerLogger = logging.MustGetLogger("server")
	logging.SetFormatter(longFormat)
}

// TurnOffLogging sets the log level to -1, causing logs not to be printed to stdout.
// This is useful to avoid otherwise verbose logging during benchmarks
func TurnOff() {
	logging.SetLevel(-1, clientModule)
	logging.SetLevel(-1, serverModule)
}
