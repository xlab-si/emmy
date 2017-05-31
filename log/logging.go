package log

import "github.com/op/go-logging"

var longFormat = logging.MustStringFormatter(
	`%{color}[%{module}] %{time:15:04:05.000} %{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

var shortFormat = logging.MustStringFormatter(
	`%{color}%{shortfunc} ▶ %{level:.4s} %{id:03x}%{color:reset} %{message}`,
)

var ClientLogger, ServerLogger *logging.Logger

func init() {
	ClientLogger = logging.MustGetLogger("server")
	ServerLogger = logging.MustGetLogger("client")
	logging.SetFormatter(longFormat)
}
