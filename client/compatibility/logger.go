/*
 * Copyright 2017 XLAB d.o.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package compatibility

import (
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/log"
)

// Supported log levels.
const (
	DEBUG    = log.DEBUG
	INFO     = log.INFO
	NOTICE   = log.NOTICE
	WARNING  = log.WARNING
	ERROR    = log.ERROR
	CRITICAL = log.CRITICAL
)

// Logger wraps a concrete *log.StdoutLogger implementation. It can be constructed by the client
// application in order to override default logger provided by the client package.
type Logger struct {
	*log.StdoutLogger
}

// NewLogger constructs a *Logger with a fixed format and configurable log level.
func NewLogger(logLevel string) (*Logger, error) {
	logger, err := log.NewStdoutLogger("client", string(logLevel), log.FORMAT_SHORT_COLORLESS)
	if err != nil {
		return nil, err
	}

	return &Logger{
		StdoutLogger: logger,
	}, nil
}

// SetLogger propagates the given *Logger to client package, around which this package wraps.
func SetLogger(logger *Logger) {
	client.SetLogger(logger.StdoutLogger)
}
