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

package cli

// This file contains definitions for all the command-line flags to be used with different commands
// or subcommands of the emmy CLI.

import (
	"path/filepath"

	"github.com/urfave/cli"
	"github.com/xlab-si/emmy/config"
)

// logLevelFlag indicates the log level applied to client/server loggers.
var logLevelFlag = cli.StringFlag{
	Name:  "loglevel, l",
	Value: "info",
	Usage: "debug|info|notice|error|critical",
}

// logFilePathFlag indicates a path to the log file used by the server (optional).
var logFilePathFlag = cli.StringFlag{
	Name:  "logfile",
	Value: "",
	Usage: "`PATH` to the file where server logs will be written (created if it doesn't exist)",
}

// keyFlag keeps the path to server's private key in PEM format
// (for establishing a secure channel with the server).
var keyFlag = cli.StringFlag{
	Name:  "key",
	Value: filepath.Join(config.LoadTestdataDir(), "server.key"),
	Usage: "`PATH` to server key file",
}

// certFlag keeps the path to server's certificate in PEM format
// (for establishing a secure channel with the server).
var certFlag = cli.StringFlag{
	Name:  "cert",
	Value: filepath.Join(config.LoadTestdataDir(), "server.pem"),
	Usage: "`PATH` to servers certificate file",
}

// caCertFlag keeps the path to CA's certificate in PEM format
// (for establishing a secure channel with the server).
var caCertFlag = cli.StringFlag{
	Name:  "cacert",
	Value: filepath.Join(config.LoadTestdataDir(), "server.pem"),
	Usage: "`PATH` to certificate file of the CA that issued emmy server's certificate",
}

// sysCertPoolFlag indicates whether a client should use system's certificate pool to validate
// the server's certificate..
var sysCertPoolFlag = cli.BoolFlag{
	Name:  "syscertpool",
	Usage: "Whether to use host system's certificate pool to validate the server",
}

// serverNameOverrideFlag allows the client to skip validation of the server's hostname when
// checking its CN. Instead, CN from the server's certificate must match the value provided by
// serverNameOverride flag.
var serverNameOverrideFlag = cli.StringFlag{
	Name:  "servername",
	Value: "",
	Usage: "Name of emmy server for overriding the server name stated in cert's CN",
}

// portFlag indicates the port where emmy server will listen.
var portFlag = cli.IntFlag{
	Name:  "port, p",
	Value: config.LoadServerPort(),
	Usage: "`PORT` where emmy server will listen for client connections",
}

// serverEndpointFlag points to the endpoint at which emmy clients will contact emmy server.
var serverEndpointFlag = cli.StringFlag{
	Name:  "server",
	Value: config.LoadServerEndpoint(),
	Usage: "`URI` of emmy server in the form serverHost:serverPort",
}

// nClientsFlag indicates the number of (either concurrent or sequential) clients to run.
var nClientsFlag = cli.IntFlag{
	Name:  "nclients, n",
	Value: 1,
	Usage: "How many clients to run",
}

// concurrencyFlag indicates whether to run clients concurrently or not.
var concurrencyFlag = cli.BoolFlag{
	Name:  "concurrent",
	Usage: "Whether to run clients concurrently or not",
}

// protocolVariantFlag indicates which protocol variant to demonstrate.
var protocolVariantFlag = cli.StringFlag{
	Name:  "variant, v",
	Value: "sigma",
	Usage: "sigma|zkp|zkpok",
}

// protocolSecretFlag keeps the secret value used to bootstrap a given protocol.
var protocolSecretFlag = cli.Int64Flag{
	Name:  "secret",
	Value: 121212121,
}

// protocolLabelFlag keeps the label used to bootstrap cspaillier verifiable encryption.
var protocolLabelFlag = cli.Int64Flag{
	Name:  "label",
	Value: 340002223232,
}

// protocolPubKeyFlag keeps the path to the public key file of the verifier used in cspaillier
// verifiable encryption protocol.
var protocolPubKeyFlag = cli.StringFlag{
	Name:  "pubkey",
	Value: filepath.Join(config.LoadKeyDirFromConfig(), "cspaillierpubkey.txt"),
	Usage: "`PATH` to the verifier's public key file",
}

// serverFlags are the flags used by the server CLI commands.
var serverFlags = []cli.Flag{
	portFlag,
	certFlag,
	keyFlag,
	logFilePathFlag,
	logLevelFlag,
}

// clientFlags are flags common to all client CLI subcommands, regardless of the protocol.
var clientFlags = []cli.Flag{
	nClientsFlag,
	concurrencyFlag,
	serverEndpointFlag,
	serverNameOverrideFlag,
	caCertFlag,
	sysCertPoolFlag,
	logLevelFlag,
}
