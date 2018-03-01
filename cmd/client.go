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
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"io/ioutil"

	"path/filepath"

	"github.com/urfave/cli"
	"github.com/xlab-si/emmy/client"
	"github.com/xlab-si/emmy/config"
	"github.com/xlab-si/emmy/crypto/common"
	"github.com/xlab-si/emmy/crypto/groups"
	"github.com/xlab-si/emmy/log"
	pb "github.com/xlab-si/emmy/protobuf"
	"google.golang.org/grpc"
)

// logLevelFlag indicates the log level applied to client/server loggers.
var logLevelFlag = cli.StringFlag{
	Name:  "loglevel, l",
	Value: "info",
	Usage: "debug|info|notice|error|critical",
}

var ClientCmd = cli.Command{
	Name:  "client",
	Usage: "A client (prover) that wants to prove something to the server (verifier)",
	// clientFlags are flags common to all client CLI subcommands, regardless of the protocol.
	Flags:       clientFlags,
	Subcommands: clientSubcommands,
}

var clientFlags = []cli.Flag{
	// nClientsFlag indicates the number of (either concurrent or sequential) clients to run.
	cli.IntFlag{
		Name:  "nclients, n",
		Value: 1,
		Usage: "How many clients to run",
	},
	// serverEndpointFlag points to the endpoint at which emmy clients will contact emmy server.
	cli.StringFlag{
		Name:  "server",
		Value: config.LoadServerEndpoint(),
		Usage: "`URI` of emmy server in the form serverHost:serverPort",
	},
	// serverNameOverrideFlag allows the client to skip validation of the server's hostname when
	// checking its CN. Instead, CN from the server's certificate must match the value provided by
	// serverNameOverride flag.
	cli.StringFlag{
		Name:  "servername",
		Value: "",
		Usage: "Name of emmy server for overriding the server name stated in cert's CN",
	},
	// caCertFlag keeps the path to CA's certificate in PEM format
	// (for establishing a secure channel with the server).
	cli.StringFlag{
		Name:  "cacert",
		Value: filepath.Join(config.LoadTestdataDir(), "server.pem"),
		Usage: "`PATH` to certificate file of the CA that issued emmy server's certificate",
	},

	// sysCertPoolFlag indicates whether a client should use system's certificate pool to validate
	// the server's certificate..
	cli.BoolFlag{
		Name:  "syscertpool",
		Usage: "Whether to use host system's certificate pool to validate the server",
	},
	// timeoutFlag indicates the timeout (in seconds) for establishing connection to the server.
	// If connection cannot be established before the timeout, the client fails.
	cli.IntFlag{
		Name:  "timeout, t",
		Value: config.LoadTimeout(),
		Usage: "timeout (in seconds) for establishing connection with the server",
	},
	logLevelFlag,
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

// clientSubcommands represent different protocols that can be executed by clients.
var clientSubcommands = []cli.Command{
	{
		Name:     "pedersen",
		Usage:    "Pedersen commitments (modular)",
		Category: "Commitment schemes",
		Flags:    []cli.Flag{protocolVariantFlag, protocolSecretFlag},
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				pbVariant, err := parseSchema(ctx.String("variant"))
				if err != nil {
					return err
				}
				group := config.LoadSchnorrGroup()
				secret := big.NewInt(ctx.Int64("secret"))
				client, err := client.NewPedersenClient(conn, pbVariant, group, secret)
				if err != nil {
					return fmt.Errorf("error creating client: %v", err)
				}
				return client.Run()
			})
		},
	},
	{
		Name:     "pedersen_ec",
		Usage:    "Pedersen commitments (elliptic curves)",
		Category: "Commitment schemes",
		Flags:    []cli.Flag{protocolSecretFlag},
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				secret := big.NewInt(ctx.Int64("secret"))
				curve := groups.P256
				client, err := client.NewPedersenECClient(conn, secret, curve)
				if err != nil {
					return fmt.Errorf("error creating client: %v", err)
				}
				return client.Run()
			})
		},
	},
	{
		Name:     "schnorr",
		Usage:    "Schnorr protocol (modular)",
		Category: "Discrete logatithm proofs",
		Flags:    []cli.Flag{protocolSecretFlag, protocolVariantFlag},
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				pbVariant, err := parseSchema(ctx.String("variant"))
				if err != nil {
					return err
				}
				group := config.LoadSchnorrGroup()
				secret := big.NewInt(ctx.Int64("secret"))
				client, err := client.NewSchnorrClient(conn, pbVariant, group, secret)
				if err != nil {
					return fmt.Errorf("error creating client: %v", err)
				}
				return client.Run()
			})
		},
	},
	{
		Name:     "schnorr_ec",
		Usage:    "Schnorr protocol (elliptic curves)",
		Category: "Discrete logatithm proofs",
		Flags:    []cli.Flag{protocolSecretFlag, protocolVariantFlag},
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				group := config.LoadSchnorrGroup()
				pbVariant, err := parseSchema(ctx.String("variant"))
				if err != nil {
					return err
				}
				secret := big.NewInt(ctx.Int64("secret"))
				client, err := client.NewSchnorrClient(conn, pbVariant, group, secret)
				if err != nil {
					return fmt.Errorf("error creating client: %v", err)
				}
				return client.Run()
			})
		},
	},
	{
		Name:     "cspaillier",
		Usage:    "Camenisch-Shoup verifiable encryption",
		Category: "Encryption",
		Flags:    []cli.Flag{protocolSecretFlag, protocolLabelFlag, protocolPubKeyFlag},
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				secret := common.GetRandomInt(big.NewInt(ctx.Int64("secret")))
				label := common.GetRandomInt(big.NewInt(ctx.Int64("label")))
				pubKey := ctx.String("pubkey")
				client, err := client.NewCSPaillierClient(conn, pubKey, secret, label)
				if err != nil {
					return fmt.Errorf("error creating client: %v", err)
				}
				return client.Run()
			})
		},
	},
	{
		Name:     "info",
		Usage:    "Fetch information about the service provider",
		Category: "Info",
		Action: func(ctx *cli.Context) error {
			return run(ctx.Parent(), ctx, func(ctx *cli.Context, conn *grpc.ClientConn) error {
				_, err := client.GetServiceInfo(conn)
				return err
			})
		},
	},
}

// run accepts pointers to parent (command) and child (subcommand) contexts in order to read
// appropriate command line flags and run a client function either sequentially or concurrently.
// It is supposed to be used as a wrapper around CLI subcommand functions that
// execute client-side of the chosen protocol.
func run(ctx, subCmdCtx *cli.Context, f func(ctx *cli.Context, conn *grpc.ClientConn) error) error {
	var err error
	logger, err := log.NewStdoutLogger("client", ctx.String("loglevel"), log.FORMAT_SHORT)
	if err != nil {
		return cli.NewExitError(err.Error(), 2)
	}
	client.SetLogger(logger)

	// configure how clients will access emmy server via TLS.
	var connCfg *client.ConnectionConfig
	if ctx.Bool("syscertpool") {
		connCfg = client.NewConnectionConfig(ctx.String("server"), "", nil,
			ctx.Int("t"))
	} else {
		caCert, err := ioutil.ReadFile(ctx.String("cacert"))
		if err != nil {
			return cli.NewExitError(err.Error(), 2)
		}
		connCfg = client.NewConnectionConfig(ctx.String("server"), ctx.String("servername"),
			caCert, ctx.Int("t"))
	}

	// conn is a connection to emmy server.
	// In case we are running more than one client, conn will be shared among all the clients.
	// We made it global because it is needed in both 'Before' and 'After' actions of the clientCmd.
	var conn *grpc.ClientConn

	// Establish a connection to emmy server
	conn, err = client.GetConnection(connCfg)
	if err != nil {
		return cli.NewExitError(fmt.Sprintf("Cannot connect to gRPC server: %v", err), 2)
	}
	defer conn.Close()

	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < ctx.Int("n"); i++ {
		fmt.Printf("***Running client #%d***\n", i+1)
		if ctx.Bool("concurrent") {
			wg.Add(1)
			go func() {
				err = f(subCmdCtx, conn)
				defer wg.Done()
			}()
		} else {
			err = f(subCmdCtx, conn)
		}
	}
	wg.Wait()
	elapsed := time.Since(start)

	// In case the function 'f' returned an error, signal it to the CLI. It means client
	// is in error.
	if err != nil {
		return cli.NewExitError(err.Error(), 1)
	}

	fmt.Printf("***Time: %v seconds***\n", elapsed.Seconds())
	return nil
}

// parseSchema parses string equivalents of protocol's variant and returns
// pb.SchemaVariant. If the user requested a variant that doesn't exist, returns an error.
func parseSchema(schemaVariant string) (pb.SchemaVariant, error) {
	variant, success := pb.SchemaVariant_value[strings.ToUpper(schemaVariant)]
	if !success {
		return 0, fmt.Errorf("invalid schema: %s", schemaVariant)
	}
	return pb.SchemaVariant(variant), nil
}
