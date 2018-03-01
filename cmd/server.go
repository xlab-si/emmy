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

package cmd

import (
	"path/filepath"

	"github.com/urfave/cli"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/log"
	"github.com/xlab-si/emmy/server"
)

var ServerCmd = cli.Command{
	Name:  "server",
	Usage: "A server (verifier) that verifies clients (provers)",
	Subcommands: []cli.Command{
		{
			Name:  "start",
			Usage: "Starts emmy server",
			Flags: serverFlags,
			Action: func(ctx *cli.Context) error {
				err := startEmmyServer(
					ctx.Int("port"),
					ctx.String("cert"),
					ctx.String("key"),
					ctx.String("db"),
					ctx.String("logfile"),
					ctx.String("loglevel"))
				if err != nil {
					return cli.NewExitError(err, 1)
				}
				return nil
			},
		},
	},
}

// serverFlags are the flags used by the server CLI commands.
var serverFlags = []cli.Flag{
	// portFlag indicates the port where emmy server will listen.
	cli.IntFlag{
		Name:  "port, p",
		Value: config.LoadServerPort(),
		Usage: "`PORT` where emmy server will listen for client connections",
	},
	// certFlag keeps the path to server's certificate in PEM format
	// (for establishing a secure channel with the server).
	cli.StringFlag{
		Name:  "cert",
		Value: filepath.Join(config.LoadTestdataDir(), "server.pem"),
		Usage: "`PATH` to servers certificate file",
	},
	// keyFlag keeps the path to server's private key in PEM format
	// (for establishing a secure channel with the server).
	cli.StringFlag{
		Name:  "key",
		Value: filepath.Join(config.LoadTestdataDir(), "server.key"),
		Usage: "`PATH` to server key file",
	},
	// dbEndpointFlag points to the endpoint at which emmy server will contact redis database.
	cli.StringFlag{
		Name:  "db",
		Value: config.LoadRegistrationDBAddress(),
		Usage: "`URI` of redis database to hold registration keys, in the form redisHost:redisPort",
	},
	// logFilePathFlag indicates a path to the log file used by the server (optional).
	cli.StringFlag{
		Name:  "logfile",
		Value: "",
		Usage: "`PATH` to the file where server logs will be written (created if it doesn't exist)",
	},
	logLevelFlag,
}

// startEmmyServer configures and starts the gRPC server at the desired port
func startEmmyServer(port int, certPath, keyPath, dbAddress, logFilePath, logLevel string) error {
	var err error
	var logger log.Logger

	if logFilePath == "" {
		logger, err = log.NewStdoutLogger("server", logLevel, log.FORMAT_LONG)
	} else {
		logger, err = log.NewStdoutFileLogger("server", logFilePath, logLevel, log.FORMAT_LONG,
			log.FORMAT_LONG_COLORLESS)
	}
	if err != nil {
		return err
	}

	srv, err := server.NewServer(certPath, keyPath, dbAddress, logger)
	if err != nil {
		return err
	}

	srv.EnableTracing()
	return srv.Start(port)
}
